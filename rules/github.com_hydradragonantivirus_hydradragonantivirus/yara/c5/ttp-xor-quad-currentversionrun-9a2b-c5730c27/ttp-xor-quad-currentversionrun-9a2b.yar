rule TTP_XOR_QUAD_CurrentVersionRun_9a2b {
  strings:
    $key_9a2b = { c9 44 [2] ed 4a [2] c6 66 [2] e8 44 [2] fc 5f [2] f3 45 [2] ed 58 [2] ef 59 [2] f4 5f [2] e8 58 [2] f4 77 }

  condition:
    any of them
}