rule PEiD_00588_EXE2COM__regular__ {
  meta:
    description = "[EXE2COM (regular)]"
    ep_only     = "true"

  strings:
    $a = { E9 8C CA 81 C3 ?? ?? 3B 16 ?? ?? 76 ?? BA ?? ?? B4 09 CD 21 CD 20 0D }

  condition:
    $a
}