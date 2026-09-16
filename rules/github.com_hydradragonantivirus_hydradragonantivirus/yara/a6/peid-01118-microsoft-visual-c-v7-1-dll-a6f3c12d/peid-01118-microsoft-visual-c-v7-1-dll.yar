rule PEiD_01118_Microsoft_Visual_C___v7_1_DLL_ {
  meta:
    description = "[Microsoft Visual C++ v7.1 DLL]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 E4 53 56 57 89 65 E8 C7 45 E4 01 00 00 00 C7 45 FC }

  condition:
    $a
}