rule TTP_XOR_QUAD_CurrentVersionRun_9a73 {
  strings:
    $key_9a73 = { c9 1c [2] ed 12 [2] c6 3e [2] e8 1c [2] fc 07 [2] f3 1d [2] ed 00 [2] ef 01 [2] f4 07 [2] e8 00 [2] f4 2f }

  condition:
    any of them
}