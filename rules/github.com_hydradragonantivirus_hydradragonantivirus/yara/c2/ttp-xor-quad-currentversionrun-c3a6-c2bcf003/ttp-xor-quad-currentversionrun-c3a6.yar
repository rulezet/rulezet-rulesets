rule TTP_XOR_QUAD_CurrentVersionRun_c3a6 {
  strings:
    $key_c3a6 = { 90 c9 [2] b4 c7 [2] 9f eb [2] b1 c9 [2] a5 d2 [2] aa c8 [2] b4 d5 [2] b6 d4 [2] ad d2 [2] b1 d5 [2] ad fa }

  condition:
    any of them
}