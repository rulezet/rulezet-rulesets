rule PEiD_03523_yoda_s_Protector_1_01____Ashkbiz_Danehkar__h__ {
  meta:
    description = "[yoda's Protector 1.01 -> Ashkbiz Danehkar (h)]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 }

  condition:
    $a
}