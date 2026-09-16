rule PEiD_02439_UPX_v0_71__DLL_ {
  meta:
    description = "[UPX v0.71 [DLL]"
    ep_only     = "true"

  strings:
    $a = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 }

  condition:
    $a
}