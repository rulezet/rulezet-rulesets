rule TTP_XOR_QUAD_CurrentVersionRun_9a63 {
  strings:
    $key_9a63 = { c9 0c [2] ed 02 [2] c6 2e [2] e8 0c [2] fc 17 [2] f3 0d [2] ed 10 [2] ef 11 [2] f4 17 [2] e8 10 [2] f4 3f }

  condition:
    any of them
}