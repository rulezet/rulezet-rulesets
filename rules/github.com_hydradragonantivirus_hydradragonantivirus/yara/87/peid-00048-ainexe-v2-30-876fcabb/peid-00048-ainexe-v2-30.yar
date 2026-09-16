rule PEiD_00048_AINEXE_v2_30_ {
  meta:
    description = "[AINEXE v2.30]"
    ep_only     = "true"

  strings:
    $a = { 0E 07 B9 ?? ?? BE ?? ?? 33 FF FC F3 A4 A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8 }

  condition:
    $a
}