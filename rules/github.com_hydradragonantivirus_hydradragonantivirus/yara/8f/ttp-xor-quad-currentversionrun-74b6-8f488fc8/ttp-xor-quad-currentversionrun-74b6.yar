rule TTP_XOR_QUAD_CurrentVersionRun_74b6 {
  strings:
    $key_74b6 = { 27 d9 [2] 03 d7 [2] 28 fb [2] 06 d9 [2] 12 c2 [2] 1d d8 [2] 03 c5 [2] 01 c4 [2] 1a c2 [2] 06 c5 [2] 1a ea }

  condition:
    any of them
}