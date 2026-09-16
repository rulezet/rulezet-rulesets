rule TTP_XOR_QUAD_CurrentVersionRun_9a46 {
  strings:
    $key_9a46 = { c9 29 [2] ed 27 [2] c6 0b [2] e8 29 [2] fc 32 [2] f3 28 [2] ed 35 [2] ef 34 [2] f4 32 [2] e8 35 [2] f4 1a }

  condition:
    any of them
}