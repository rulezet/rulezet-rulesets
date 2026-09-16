rule PEiD_01071_Microsoft_Visual_C___6_0_DLL__Debug__ {
  meta:
    description = "[Microsoft Visual C++ 6.0 DLL (Debug)]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 ?? ?? 83 }

  condition:
    $a
}