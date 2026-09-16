rule PEiD_03365_VProtector_V1_3X____vcasm_ {
  meta:
    description = "[VProtector V1.3X -> vcasm]"
    ep_only     = "false"

  strings:
    $a = { 00 00 00 00 55 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 64 69 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}