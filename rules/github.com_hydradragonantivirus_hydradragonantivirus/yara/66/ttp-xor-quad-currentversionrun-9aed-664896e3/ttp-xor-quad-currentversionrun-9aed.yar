rule TTP_XOR_QUAD_CurrentVersionRun_9aed {
  strings:
    $key_9aed = { c9 82 [2] ed 8c [2] c6 a0 [2] e8 82 [2] fc 99 [2] f3 83 [2] ed 9e [2] ef 9f [2] f4 99 [2] e8 9e [2] f4 b1 }

  condition:
    any of them
}