rule PEiD_02409_UPX_0_50___0_70_ {
  meta:
    description = "[UPX 0.50 - 0.70]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 83 E8 3D }

  condition:
    $a
}