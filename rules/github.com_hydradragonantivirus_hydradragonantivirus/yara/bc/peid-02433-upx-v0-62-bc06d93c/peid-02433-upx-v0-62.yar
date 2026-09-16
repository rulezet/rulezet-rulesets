rule PEiD_02433_UPX_v0_62_ {
  meta:
    description = "[UPX v0.62]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }

  condition:
    $a
}