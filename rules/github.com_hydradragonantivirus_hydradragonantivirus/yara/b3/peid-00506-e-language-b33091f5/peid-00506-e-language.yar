rule PEiD_00506_E_language_ {
  meta:
    description = "[E language]"
    ep_only     = "true"

  strings:
    $a = { E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF }

  condition:
    $a
}