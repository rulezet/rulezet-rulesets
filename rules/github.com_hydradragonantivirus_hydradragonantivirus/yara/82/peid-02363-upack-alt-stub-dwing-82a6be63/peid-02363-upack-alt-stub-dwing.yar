rule PEiD_02363_UPack_Alt_Stub____Dwing_ {
  meta:
    description = "[UPack Alt Stub -> Dwing]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 09 00 00 00 C3 F6 00 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD }

  condition:
    $a
}