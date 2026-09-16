rule TTP_XOR_QUAD_CurrentVersionRun_4d72 {
  strings:
    $key_4d72 = { 1e 1d [2] 3a 13 [2] 11 3f [2] 3f 1d [2] 2b 06 [2] 24 1c [2] 3a 01 [2] 38 00 [2] 23 06 [2] 3f 01 [2] 23 2e }

  condition:
    any of them
}