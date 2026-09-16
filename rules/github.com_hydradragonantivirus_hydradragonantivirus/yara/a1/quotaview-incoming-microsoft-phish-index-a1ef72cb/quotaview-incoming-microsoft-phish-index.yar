rule quotaview_incoming_microsoft_phish_index {
  meta:
    description = "microsoft-phish - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-08-11"
    hash1       = "bec638fbc9edfbd8e65ee9dec04b921d12eb51a7cfd2862c348b4780b729b500"

  strings:
    $s1 = "header(\"location: login.php?cmd=login_submit&id=$praga$praga&session=$praga$praga\");" fullword ascii
    $s2 = "require_once 'hostname.php';" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}