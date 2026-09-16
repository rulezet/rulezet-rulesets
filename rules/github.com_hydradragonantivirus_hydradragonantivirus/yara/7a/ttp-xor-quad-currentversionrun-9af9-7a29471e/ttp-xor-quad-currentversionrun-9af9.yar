rule TTP_XOR_QUAD_CurrentVersionRun_9af9 {
  strings:
    $key_9af9 = { c9 96 [2] ed 98 [2] c6 b4 [2] e8 96 [2] fc 8d [2] f3 97 [2] ed 8a [2] ef 8b [2] f4 8d [2] e8 8a [2] f4 a5 }

  condition:
    any of them
}