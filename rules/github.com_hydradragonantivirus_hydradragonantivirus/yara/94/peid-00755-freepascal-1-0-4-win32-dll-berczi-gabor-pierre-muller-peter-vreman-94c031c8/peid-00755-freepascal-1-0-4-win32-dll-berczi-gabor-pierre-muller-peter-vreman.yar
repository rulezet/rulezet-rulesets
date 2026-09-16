rule PEiD_00755_FreePascal_1_0_4_Win32_DLL_____Berczi_Gabor__Pierre_Muller___Peter_Vreman__ {
  meta:
    description = "[FreePascal 1.0.4 Win32 DLL -> (Berczi Gabor, Pierre Muller & Peter Vreman)]"
    ep_only     = "false"

  strings:
    $a = { C6 05 ?? ?? ?? ?? 00 55 89 E5 53 56 57 8B 7D 08 89 3D ?? ?? ?? ?? 8B 7D 0C 89 3D ?? ?? ?? ?? 8B 7D 10 89 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5B 5D C2 0C 00 }

  condition:
    $a
}