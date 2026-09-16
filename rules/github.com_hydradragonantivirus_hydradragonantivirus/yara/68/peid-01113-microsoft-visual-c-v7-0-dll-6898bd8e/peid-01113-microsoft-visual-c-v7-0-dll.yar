rule PEiD_01113_Microsoft_Visual_C___v7_0_DLL_ {
  meta:
    description = "[Microsoft Visual C++ v7.0 DLL]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 ?? ?? 83 }

  condition:
    $a
}