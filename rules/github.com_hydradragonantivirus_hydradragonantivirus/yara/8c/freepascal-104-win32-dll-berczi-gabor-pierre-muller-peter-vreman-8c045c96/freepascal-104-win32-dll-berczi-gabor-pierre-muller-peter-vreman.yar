import "pe"
rule _FreePascal_104_Win32_DLL__Berczi_Gabor_Pierre_Muller__Peter_Vreman_ {
  meta:
    description = "FreePascal 1.0.4 Win32 DLL -> (Berczi Gabor, Pierre Muller & Peter Vreman)"

  strings:
    $0 = { C6 05 ?? ?? ?? ?? 00 55 89 E5 53 56 57 8B 7D 08 89 3D ?? ?? ?? ?? 8B 7D 0C 89 3D ?? ?? ?? ?? 8B 7D 10 89 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5B 5D C2 0C 00 }

  condition:
    $0 at pe.entry_point
}