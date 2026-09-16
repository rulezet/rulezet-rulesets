rule TTP_XOR_QUAD_CurrentVersionRun_6fb7 {
  strings:
    $key_6fb7 = { 3c d8 [2] 18 d6 [2] 33 fa [2] 1d d8 [2] 09 c3 [2] 06 d9 [2] 18 c4 [2] 1a c5 [2] 01 c3 [2] 1d c4 [2] 01 eb }

  condition:
    any of them
}