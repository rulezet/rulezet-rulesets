rule TTP_XOR_QUAD_CurrentVersionRun_9a13 {
  strings:
    $key_9a13 = { c9 7c [2] ed 72 [2] c6 5e [2] e8 7c [2] fc 67 [2] f3 7d [2] ed 60 [2] ef 61 [2] f4 67 [2] e8 60 [2] f4 4f }

  condition:
    any of them
}