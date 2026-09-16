rule TTP_XOR_QUAD_CurrentVersionRun_9af8 {
  strings:
    $key_9af8 = { c9 97 [2] ed 99 [2] c6 b5 [2] e8 97 [2] fc 8c [2] f3 96 [2] ed 8b [2] ef 8a [2] f4 8c [2] e8 8b [2] f4 a4 }

  condition:
    any of them
}