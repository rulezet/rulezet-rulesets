rule PEiD_01055_Microsoft_Visual_Basic_v6_0_DLL_ {
  meta:
    description = "[Microsoft Visual Basic v6.0 DLL]"
    ep_only     = "true"

  strings:
    $a = { 5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF }

  condition:
    $a
}