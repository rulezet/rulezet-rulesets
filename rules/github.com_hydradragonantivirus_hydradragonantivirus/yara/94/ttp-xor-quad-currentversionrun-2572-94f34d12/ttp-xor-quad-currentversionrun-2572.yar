rule TTP_XOR_QUAD_CurrentVersionRun_2572 {
  strings:
    $key_2572 = { 76 1d [2] 52 13 [2] 79 3f [2] 57 1d [2] 43 06 [2] 4c 1c [2] 52 01 [2] 50 00 [2] 4b 06 [2] 57 01 [2] 4b 2e }

  condition:
    any of them
}