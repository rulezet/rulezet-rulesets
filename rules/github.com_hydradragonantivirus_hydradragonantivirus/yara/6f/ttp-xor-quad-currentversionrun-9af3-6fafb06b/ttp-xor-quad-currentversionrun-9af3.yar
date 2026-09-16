rule TTP_XOR_QUAD_CurrentVersionRun_9af3 {
  strings:
    $key_9af3 = { c9 9c [2] ed 92 [2] c6 be [2] e8 9c [2] fc 87 [2] f3 9d [2] ed 80 [2] ef 81 [2] f4 87 [2] e8 80 [2] f4 af }

  condition:
    any of them
}