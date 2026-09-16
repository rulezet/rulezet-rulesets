rule PEiD_01117_Microsoft_Visual_C___v7_1_DLL_ {
  meta:
    description = "[Microsoft Visual C++ v7.1 DLL]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? 40 00 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 }

  condition:
    $a
}