rule TTP_XOR_QUAD_CurrentVersionRun_e9c9 {
  strings:
    $key_e9c9 = { ba a6 [2] 9e a8 [2] b5 84 [2] 9b a6 [2] 8f bd [2] 80 a7 [2] 9e ba [2] 9c bb [2] 87 bd [2] 9b ba [2] 87 95 }

  condition:
    any of them
}