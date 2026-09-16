rule PEiD_00432_CrypKey_V5_6_X_DLL____Kenonic_Controls_Ltd__ {
  meta:
    description = "[CrypKey V5.6.X DLL -> Kenonic Controls Ltd.]"
    ep_only     = "true"

  strings:
    $a = { 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8 }

  condition:
    $a
}