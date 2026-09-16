rule PEiD_01107_Microsoft_Visual_C___v6_0_SPx_ {
  meta:
    description = "[Microsoft Visual C++ v6.0 SPx]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22 }

  condition:
    $a
}