rule PEiD_01612_Pelles_C_4_50_DLL__X86_CRT_LIB__ {
  meta:
    description = "[Pelles C 4.50 DLL (X86 CRT-LIB)]"
    ep_only     = "false"

  strings:
    $a = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D ?? ?? ?? ?? 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }

  condition:
    $a
}