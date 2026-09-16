rule infected_08_25_18_crd_phishing_index {
  meta:
    description = "phishing - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-25"
    hash1       = "ab9aaaef4c579a9dd2449adb375287ad4330437cfff5495769cee4aac4e16e9b"

  strings:
    $s1 = "while(false !== ( $file = readdir($dir)) ) {" fullword ascii
    $s2 = "include('entreeBam/antibots.php');" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}