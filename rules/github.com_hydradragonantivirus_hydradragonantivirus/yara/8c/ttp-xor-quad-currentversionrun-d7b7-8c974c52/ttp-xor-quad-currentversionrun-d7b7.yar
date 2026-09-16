rule TTP_XOR_QUAD_CurrentVersionRun_d7b7 {
  strings:
    $key_d7b7 = { 84 d8 [2] a0 d6 [2] 8b fa [2] a5 d8 [2] b1 c3 [2] be d9 [2] a0 c4 [2] a2 c5 [2] b9 c3 [2] a5 c4 [2] b9 eb }

  condition:
    any of them
}