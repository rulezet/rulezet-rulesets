rule PEiD_01945_REC_v0_32_ {
  meta:
    description = "[REC v0.32]"
    ep_only     = "true"

  strings:
    $a = { 06 1E 52 B8 ?? ?? 1E CD 21 86 E0 3D }

  condition:
    $a
}