rule PEiD_00952_KByS_V0_28_DLL____shoooo___Sign_by_fly_ {
  meta:
    description = "[KByS V0.28 DLL -> shoooo ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 03 C2 FF E0 ?? ?? ?? ?? 60 E8 00 00 00 00 }

  condition:
    $a
}