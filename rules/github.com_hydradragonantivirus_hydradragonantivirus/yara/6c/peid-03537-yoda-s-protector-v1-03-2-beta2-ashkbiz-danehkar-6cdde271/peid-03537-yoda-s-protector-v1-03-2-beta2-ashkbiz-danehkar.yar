rule PEiD_03537_Yoda_s_Protector_v1_03_2_Beta2____Ashkbiz_Danehkar_ {
  meta:
    description = "[Yoda's Protector v1.03.2 Beta2 -> Ashkbiz Danehkar]"
    ep_only     = "true"

  strings:
    $a = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 }

  condition:
    $a
}