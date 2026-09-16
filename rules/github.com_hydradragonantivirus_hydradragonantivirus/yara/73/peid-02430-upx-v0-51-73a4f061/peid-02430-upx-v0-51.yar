rule PEiD_02430_UPX_v0_51_ {
  meta:
    description = "[UPX v0.51]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 D8 01 ?? ?? 83 CD FF 31 DB ?? ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90 }

  condition:
    $a
}