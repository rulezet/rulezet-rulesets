rule TTP_XOR_QUAD_CurrentVersionRun_9a62 {
  strings:
    $key_9a62 = { c9 0d [2] ed 03 [2] c6 2f [2] e8 0d [2] fc 16 [2] f3 0c [2] ed 11 [2] ef 10 [2] f4 16 [2] e8 11 [2] f4 3e }

  condition:
    any of them
}