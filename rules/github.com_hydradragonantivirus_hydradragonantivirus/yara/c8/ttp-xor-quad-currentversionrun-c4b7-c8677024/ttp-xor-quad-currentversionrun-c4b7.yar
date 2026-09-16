rule TTP_XOR_QUAD_CurrentVersionRun_c4b7 {
  strings:
    $key_c4b7 = { 97 d8 [2] b3 d6 [2] 98 fa [2] b6 d8 [2] a2 c3 [2] ad d9 [2] b3 c4 [2] b1 c5 [2] aa c3 [2] b6 c4 [2] aa eb }

  condition:
    any of them
}