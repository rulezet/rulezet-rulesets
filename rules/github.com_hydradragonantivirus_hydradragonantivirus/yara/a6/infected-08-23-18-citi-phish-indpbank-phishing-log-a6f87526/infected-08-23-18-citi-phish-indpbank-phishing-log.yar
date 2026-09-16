rule infected_08_23_18_citi_phish_INDPBANK_phishing_Log {
  meta:
    description = "phishing - file Log.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-23"
    hash1       = "8d529fdadfbaae1249cdfcba67cbc792edf812442583c3a6c71469de4e6ab5cc"

  strings:
    $s1 = "header(\"Location: Logging_in.php?$hostname\").md5(time());" fullword ascii
    $s2 = "header(\"Location: index.php?invalidX$hostname\").md5(time());" fullword ascii
    $s3 = "$hostname = bin2hex ($_SERVER['HTTP_HOST']);" fullword ascii
    $s4 = "$_SESSION['PassCode'] = $PASS = $_POST['Passcode'];" fullword ascii
    $s5 = "$_SESSION['UserID'] = $USER = $_POST['IDUser'];" fullword ascii
    $s6 = "//GET HOST NAME" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (all of them)
    ) or (all of them)
}