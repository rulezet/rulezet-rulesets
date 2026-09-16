rule PEiD_00992_LZEXE_v0_91__v1_00a__2__ {
  meta:
    description = "[LZEXE v0.91, v1.00a (2)]"
    ep_only     = "true"

  strings:
    $a = { BF ?? ?? 06 89 F9 0E 41 1F 8C CB 89 FE }

  condition:
    $a
}