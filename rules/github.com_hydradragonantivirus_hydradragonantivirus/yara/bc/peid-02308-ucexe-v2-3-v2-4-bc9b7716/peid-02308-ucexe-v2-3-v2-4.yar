rule PEiD_02308_UCEXE_v2_3__v2_4_ {
  meta:
    description = "[UCEXE v2.3, v2.4]"
    ep_only     = "true"

  strings:
    $a = { 50 1E 0E 1F FC 33 F6 E8 ?? ?? 16 07 33 F6 33 FF B9 ?? ?? F3 A5 06 B8 ?? ?? 50 CB }

  condition:
    $a
}