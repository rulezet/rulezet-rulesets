rule PEiD_00664_EXE______________Liuli_ {
  meta:
    description = "[Convert Base64 to ASCII RVhFw47DhMK8w77CusOPwrLCosOGw7cgLT4gTGl1bGk=]"
    ep_only     = "false"

  strings:
    $a = { E8 53 03 00 00 8B F0 56 56 E8 98 03 00 00 8B C8 }

  condition:
    $a
}