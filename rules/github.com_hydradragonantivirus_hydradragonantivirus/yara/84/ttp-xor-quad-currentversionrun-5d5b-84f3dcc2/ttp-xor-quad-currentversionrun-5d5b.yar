rule TTP_XOR_QUAD_CurrentVersionRun_5d5b {
  strings:
    $key_5d5b = { 0e 34 [2] 2a 3a [2] 01 16 [2] 2f 34 [2] 3b 2f [2] 34 35 [2] 2a 28 [2] 28 29 [2] 33 2f [2] 2f 28 [2] 33 07 }

  condition:
    any of them
}