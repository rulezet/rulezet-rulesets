rule PEiD_01096_Microsoft_Visual_C___DLL_ {
  meta:
    description = "[Microsoft Visual C++ DLL]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C }

  condition:
    $a
}