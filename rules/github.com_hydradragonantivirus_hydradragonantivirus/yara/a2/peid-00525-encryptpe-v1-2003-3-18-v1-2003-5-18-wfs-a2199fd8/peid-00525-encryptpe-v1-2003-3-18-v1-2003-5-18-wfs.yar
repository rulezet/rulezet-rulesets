rule PEiD_00525_EncryptPE_V1_2003_3_18_V1_2003_5_18____WFS_ {
  meta:
    description = "[EncryptPE V1.2003.3.18-V1.2003.5.18 -> WFS]"
    ep_only     = "true"

  strings:
    $a = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}