rule _One_Time_blacklist_lookup_0 {
  meta:
    description = "phishing - from files One_Time.php, blacklist_lookup.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "e49e2e5599cc3b23566af92c4695593147ac21e6e174fdb43e8b224544b7780f"
    hash2       = "921abc8cd5b73ed1f639de236bfa62bf0c6cc3a8a142e403d3e24cd26f110cd4"

  strings:
    $s1  = "** private function that reads the file into array" fullword ascii
    $s2  = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
    $s3  = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
    $s4  = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
    $s5  = "** public function that returns the ip list array" fullword ascii
    $s6  = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
    $s7  = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
    $s8  = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
    $s9  = "$temp = explode( \"#\", $line );" fullword ascii
    $s10 = "# create content array" fullword ascii
    $s11 = "# remove comment and blank lines" fullword ascii
    $s12 = "$line = trim( $temp[0] );" fullword ascii
    $s13 = "$retval = $this->whitelistfile->filename( $ip, $comment );" fullword ascii
    $s14 = "$retval = $this->blacklistfile->append( $ip, $comment );" fullword ascii
    $s15 = "$retval = $this->blacklistfile->filename( $ip, $comment );" fullword ascii
    $s16 = "$retval = $this->whitelistfile->append( $ip, $comment );" fullword ascii
    $s17 = "public function filename( $type, $ip, $comment = \"\" ) {" fullword ascii
    $s18 = "$this->message = $ip . \" is whitelisted by \".$this->whitelist->message().\".\";" fullword ascii
    $s19 = "$this->message = $ip . \" is blacklisted by \".$this->blacklist->message().\".\";" fullword ascii
    $s20 = "# remove on line comments" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and (8 of them)
    ) or (all of them)
}