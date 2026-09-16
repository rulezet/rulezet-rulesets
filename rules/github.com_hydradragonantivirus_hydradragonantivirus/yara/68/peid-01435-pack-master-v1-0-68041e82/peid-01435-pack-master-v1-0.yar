rule PEiD_01435_Pack_Master_v1_0_ {
  meta:
    description = "[Pack Master v1.0]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }

  condition:
    $a
}