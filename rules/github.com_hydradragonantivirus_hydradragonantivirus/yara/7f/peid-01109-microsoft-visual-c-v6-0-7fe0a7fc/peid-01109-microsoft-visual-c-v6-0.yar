rule PEiD_01109_Microsoft_Visual_C___v6_0_ {
  meta:
    description = "[Microsoft Visual C++ v6.0]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B }

  condition:
    $a
}