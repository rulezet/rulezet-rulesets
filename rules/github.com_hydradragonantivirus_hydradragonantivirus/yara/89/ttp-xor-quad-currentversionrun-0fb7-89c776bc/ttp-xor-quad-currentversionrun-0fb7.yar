rule TTP_XOR_QUAD_CurrentVersionRun_0fb7 {
  strings:
    $key_0fb7 = { 5c d8 [2] 78 d6 [2] 53 fa [2] 7d d8 [2] 69 c3 [2] 66 d9 [2] 78 c4 [2] 7a c5 [2] 61 c3 [2] 7d c4 [2] 61 eb }

  condition:
    any of them
}