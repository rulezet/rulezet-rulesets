rule TTP_XOR_QUAD_CurrentVersionRun_58b7 {
  strings:
    $key_58b7 = { 0b d8 [2] 2f d6 [2] 04 fa [2] 2a d8 [2] 3e c3 [2] 31 d9 [2] 2f c4 [2] 2d c5 [2] 36 c3 [2] 2a c4 [2] 36 eb }

  condition:
    any of them
}