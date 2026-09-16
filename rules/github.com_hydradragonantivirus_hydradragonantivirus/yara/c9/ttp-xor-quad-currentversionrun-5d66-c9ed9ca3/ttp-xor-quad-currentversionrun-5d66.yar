rule TTP_XOR_QUAD_CurrentVersionRun_5d66 {
  strings:
    $key_5d66 = { 0e 09 [2] 2a 07 [2] 01 2b [2] 2f 09 [2] 3b 12 [2] 34 08 [2] 2a 15 [2] 28 14 [2] 33 12 [2] 2f 15 [2] 33 3a }

  condition:
    any of them
}