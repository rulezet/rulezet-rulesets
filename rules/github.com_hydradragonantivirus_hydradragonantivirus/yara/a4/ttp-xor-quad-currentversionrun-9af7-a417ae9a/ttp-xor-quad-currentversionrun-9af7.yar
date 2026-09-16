rule TTP_XOR_QUAD_CurrentVersionRun_9af7 {
  strings:
    $key_9af7 = { c9 98 [2] ed 96 [2] c6 ba [2] e8 98 [2] fc 83 [2] f3 99 [2] ed 84 [2] ef 85 [2] f4 83 [2] e8 84 [2] f4 ab }

  condition:
    any of them
}