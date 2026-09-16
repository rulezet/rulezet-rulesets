rule PEiD_01119_Microsoft_Visual_C___v7_1_DLL_ {
  meta:
    description = "[Microsoft Visual C++ v7.1 DLL]"
    ep_only     = "true"

  strings:
    $a = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 }

  condition:
    $a
}