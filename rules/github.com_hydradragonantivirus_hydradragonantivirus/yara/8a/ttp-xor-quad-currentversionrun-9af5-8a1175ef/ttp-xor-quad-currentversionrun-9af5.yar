rule TTP_XOR_QUAD_CurrentVersionRun_9af5 {
  strings:
    $key_9af5 = { c9 9a [2] ed 94 [2] c6 b8 [2] e8 9a [2] fc 81 [2] f3 9b [2] ed 86 [2] ef 87 [2] f4 81 [2] e8 86 [2] f4 a9 }

  condition:
    any of them
}