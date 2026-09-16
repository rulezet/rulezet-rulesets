rule PEiD_00866_Guardant_Stealth_aka_Novex_Dongle_ {
  meta:
    description = "[Guardant Stealth aka Novex Dongle]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 60 E8 51 FF FF FF }

  condition:
    $a
}