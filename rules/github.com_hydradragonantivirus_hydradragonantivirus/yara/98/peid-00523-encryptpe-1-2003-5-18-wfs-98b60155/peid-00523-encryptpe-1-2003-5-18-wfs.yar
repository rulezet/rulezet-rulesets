rule PEiD_00523_EncryptPE_1_2003_5_18____WFS_ {
  meta:
    description = "[EncryptPE 1.2003.5.18 -> WFS]"
    ep_only     = "true"

  strings:
    $a = { 60 9C 64 FF 35 00 00 00 00 E8 79 }

  condition:
    $a
}