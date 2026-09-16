rule PEiD_01095_Microsoft_Visual_C___DLL_ {
  meta:
    description = "[Microsoft Visual C++ DLL]"
    ep_only     = "true"

  strings:
    $a = { 53 B8 01 00 00 00 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0 }

  condition:
    $a
}