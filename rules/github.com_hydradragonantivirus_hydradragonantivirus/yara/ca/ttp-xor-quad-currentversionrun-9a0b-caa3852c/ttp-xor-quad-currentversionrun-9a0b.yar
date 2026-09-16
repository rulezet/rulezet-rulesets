rule TTP_XOR_QUAD_CurrentVersionRun_9a0b {
  strings:
    $key_9a0b = { c9 64 [2] ed 6a [2] c6 46 [2] e8 64 [2] fc 7f [2] f3 65 [2] ed 78 [2] ef 79 [2] f4 7f [2] e8 78 [2] f4 57 }

  condition:
    any of them
}