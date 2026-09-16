rule TTP_XOR_QUAD_CurrentVersionRun_5eb6 {
  strings:
    $key_5eb6 = { 0d d9 [2] 29 d7 [2] 02 fb [2] 2c d9 [2] 38 c2 [2] 37 d8 [2] 29 c5 [2] 2b c4 [2] 30 c2 [2] 2c c5 [2] 30 ea }

  condition:
    any of them
}