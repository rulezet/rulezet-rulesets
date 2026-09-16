rule PEiD_00433_CrypKey_V6_1X_DLL____CrypKey__Canada__Inc__ {
  meta:
    description = "[CrypKey V6.1X DLL -> CrypKey (Canada) Inc.]"
    ep_only     = "true"

  strings:
    $a = { 83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8 }

  condition:
    $a
}