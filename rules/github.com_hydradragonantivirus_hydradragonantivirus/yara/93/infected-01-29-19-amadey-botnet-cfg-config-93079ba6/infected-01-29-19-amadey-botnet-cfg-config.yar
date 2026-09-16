rule infected_01_29_19_amadey_botnet_cfg_config {
  meta:
    description = "amadey-botnet - file config.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "e516cd50d498bce347853598d7855f87b28104413bee41cf413af0f294f845c6"

  strings:
    $s1 = "$conf[\"observer_password\"] = \"dfda0d32069b96bf6c4ea352feffd1b2\";" fullword ascii
    $s2 = "$conf[\"password\"] = \"63a9f0ea7bb98050796b649e85481845\";" fullword ascii
    $s3 = "$conf[\"observer_login\"] = \"observer\";" fullword ascii
    $s4 = "$conf[\"login\"] = \"root\";" fullword ascii
    $s5 = "$conf[\"dbhost\"] = \"localhost\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}