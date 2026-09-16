rule TTP_XOR_QUAD_CurrentVersionRun_9af2 {
  strings:
    $key_9af2 = { c9 9d [2] ed 93 [2] c6 bf [2] e8 9d [2] fc 86 [2] f3 9c [2] ed 81 [2] ef 80 [2] f4 86 [2] e8 81 [2] f4 ae }

  condition:
    any of them
}