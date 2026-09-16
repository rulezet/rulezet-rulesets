rule PEiD_00105_App_Encryptor____Silent_Team_ {
  meta:
    description = "[App Encryptor -> Silent Team]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }

  condition:
    $a
}