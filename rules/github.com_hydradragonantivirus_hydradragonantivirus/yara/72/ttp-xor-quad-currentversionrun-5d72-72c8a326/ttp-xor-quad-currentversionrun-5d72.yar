rule TTP_XOR_QUAD_CurrentVersionRun_5d72 {
  strings:
    $key_5d72 = { 0e 1d [2] 2a 13 [2] 01 3f [2] 2f 1d [2] 3b 06 [2] 34 1c [2] 2a 01 [2] 28 00 [2] 33 06 [2] 2f 01 [2] 33 2e }

  condition:
    any of them
}