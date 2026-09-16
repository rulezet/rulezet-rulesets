rule PEiD_03530_yoda_s_Protector_1_0x____Ashkbiz_Danehkar_ {
  meta:
    description = "[yoda's Protector 1.0x -> Ashkbiz Danehkar]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 }

  condition:
    $a
}