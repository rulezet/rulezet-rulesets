rule TTP_XOR_QUAD_CurrentVersionRun_28b7 {
  strings:
    $key_28b7 = { 7b d8 [2] 5f d6 [2] 74 fa [2] 5a d8 [2] 4e c3 [2] 41 d9 [2] 5f c4 [2] 5d c5 [2] 46 c3 [2] 5a c4 [2] 46 eb }

  condition:
    any of them
}