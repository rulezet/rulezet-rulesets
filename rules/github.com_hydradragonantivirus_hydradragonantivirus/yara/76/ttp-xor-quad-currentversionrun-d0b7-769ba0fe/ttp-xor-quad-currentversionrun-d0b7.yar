rule TTP_XOR_QUAD_CurrentVersionRun_d0b7 {
  strings:
    $key_d0b7 = { 83 d8 [2] a7 d6 [2] 8c fa [2] a2 d8 [2] b6 c3 [2] b9 d9 [2] a7 c4 [2] a5 c5 [2] be c3 [2] a2 c4 [2] be eb }

  condition:
    any of them
}