rule infected_phishing_One_Time {
  meta:
    description = "phishing - file One_Time.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "e49e2e5599cc3b23566af92c4695593147ac21e6e174fdb43e8b224544b7780f"

  strings:
    $s1  = "** private function that reads the file into array" fullword ascii
    $s2  = "header(\"Location: https://chase.com/\");" fullword ascii
    $s3  = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
    $s4  = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
    $s5  = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
    $s6  = "** public function that returns the ip list array" fullword ascii
    $s7  = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
    $s8  = "$whitelistfile = 'includes/whitelist.dat', " fullword ascii
    $s9  = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
    $s10 = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
    $s11 = "$temp = explode( \"#\", $line );" fullword ascii
    $s12 = "# create content array" fullword ascii
    $s13 = "# remove comment and blank lines" fullword ascii
    $s14 = "$line = trim( $temp[0] );" fullword ascii
    $s15 = "$retval = $this->whitelistfile->filename( $ip, $comment );" fullword ascii
    $s16 = "$retval = $this->blacklistfile->append( $ip, $comment );" fullword ascii
    $s17 = "$retval = $this->blacklistfile->filename( $ip, $comment );" fullword ascii
    $s18 = "$retval = $this->whitelistfile->append( $ip, $comment );" fullword ascii
    $s19 = "public function filename( $type, $ip, $comment = \"\" ) {" fullword ascii
    $s20 = "$this->message = $ip . \" is whitelisted by \".$this->whitelist->message().\".\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}