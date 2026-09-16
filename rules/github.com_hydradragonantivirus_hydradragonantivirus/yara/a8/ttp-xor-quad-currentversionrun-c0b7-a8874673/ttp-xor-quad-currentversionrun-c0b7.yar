rule TTP_XOR_QUAD_CurrentVersionRun_c0b7 {
  strings:
    $key_c0b7 = { 93 d8 [2] b7 d6 [2] 9c fa [2] b2 d8 [2] a6 c3 [2] a9 d9 [2] b7 c4 [2] b5 c5 [2] ae c3 [2] b2 c4 [2] ae eb }

  condition:
    any of them
}