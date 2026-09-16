rule PEiD_00317_BobSoft_Mini_Delphi____BoB___BobSoft_ {
  meta:
    description = "[BobSoft Mini Delphi -> BoB / BobSoft]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 }

  condition:
    $a
}