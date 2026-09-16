rule PEiD_00431_CrypKey_V5_6_X____Kenonic_Controls_Ltd__ {
  meta:
    description = "[CrypKey V5.6.X -> Kenonic Controls Ltd.]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8 }

  condition:
    $a
}