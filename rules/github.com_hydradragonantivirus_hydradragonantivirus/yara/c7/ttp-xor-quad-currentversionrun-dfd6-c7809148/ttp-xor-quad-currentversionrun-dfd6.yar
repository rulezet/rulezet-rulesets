rule TTP_XOR_QUAD_CurrentVersionRun_dfd6 {
  strings:
    $key_dfd6 = { 8c b9 [2] a8 b7 [2] 83 9b [2] ad b9 [2] b9 a2 [2] b6 b8 [2] a8 a5 [2] aa a4 [2] b1 a2 [2] ad a5 [2] b1 8a }

  condition:
    any of them
}