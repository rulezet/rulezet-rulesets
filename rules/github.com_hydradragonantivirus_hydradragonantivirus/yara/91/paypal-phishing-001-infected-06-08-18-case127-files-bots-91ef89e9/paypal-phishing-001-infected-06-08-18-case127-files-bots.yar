rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_bots {
  meta:
    description = "case127 - file bots.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "41af449e6806caeb6c0679cecaebc0bb8b2e7b7f2b1351ed4c8788014dfdbbfa"

  strings:
    $s1 = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);" fullword ascii
    $s2 = "178.*\", \"68.65.53.71\", \"^198.25.*.*\", \"^64.106.213.*\", \"^91.103.66.*\", \"^208.91.115.*\", \"^199.30.228.*\");" fullword ascii
    $s3 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
    $s4 = "if (substr_count($hostname, $word) > 0) {" fullword ascii
    $s5 = "if(preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])){" fullword ascii
    $s6 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
    $s7 = "$bannedIP = array(\"^81.161.59.*\", \"^66.135.200.*\", \"^66.102.*.*\", \"^38.100.*.*\", \"^107.170.*.*\", \"^149.20.*.*\", \"^3" ascii
    $s8 = "if(in_array($_SERVER['REMOTE_ADDR'],$bannedIP)) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 6KB and
      (all of them)
    ) or (all of them)
}