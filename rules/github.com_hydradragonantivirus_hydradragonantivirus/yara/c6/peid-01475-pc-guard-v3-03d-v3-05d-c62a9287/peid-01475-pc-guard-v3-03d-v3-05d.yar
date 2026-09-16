rule PEiD_01475_PC_Guard_v3_03d__v3_05d_ {
  meta:
    description = "[PC-Guard v3.03d, v3.05d]"
    ep_only     = "true"

  strings:
    $a = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }

  condition:
    $a
}