rule PEiD_00951_KByS_V0_28____shoooo___Sign_by_fly_ {
  meta:
    description = "[KByS V0.28 -> shoooo ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 }

  condition:
    $a
}