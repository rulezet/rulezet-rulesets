rule TTP_XOR_QUAD_CurrentVersionRun_2573 {
  strings:
    $key_2573 = { 76 1c [2] 52 12 [2] 79 3e [2] 57 1c [2] 43 07 [2] 4c 1d [2] 52 00 [2] 50 01 [2] 4b 07 [2] 57 00 [2] 4b 2f }

  condition:
    any of them
}