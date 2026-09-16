rule PEiD_01602_PEiD_Bundle_V1_02____BoB___BobSoft_ {
  meta:
    description = "[PEiD-Bundle V1.02 -> BoB / BobSoft]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

  condition:
    $a
}