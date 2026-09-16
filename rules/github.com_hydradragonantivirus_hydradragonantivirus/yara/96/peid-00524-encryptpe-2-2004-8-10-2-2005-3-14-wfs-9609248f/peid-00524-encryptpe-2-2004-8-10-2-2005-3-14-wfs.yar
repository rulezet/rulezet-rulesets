rule PEiD_00524_EncryptPE_2_2004_8_10___2_2005_3_14____WFS_ {
  meta:
    description = "[EncryptPE 2.2004.8.10 - 2.2005.3.14 -> WFS]"
    ep_only     = "true"

  strings:
    $a = { 60 9C 64 FF 35 00 00 00 00 E8 7A }

  condition:
    $a
}