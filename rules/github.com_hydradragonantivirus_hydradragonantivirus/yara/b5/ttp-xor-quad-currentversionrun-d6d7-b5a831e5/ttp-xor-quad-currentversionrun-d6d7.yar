rule TTP_XOR_QUAD_CurrentVersionRun_d6d7 {
  strings:
    $key_d6d7 = { 85 b8 [2] a1 b6 [2] 8a 9a [2] a4 b8 [2] b0 a3 [2] bf b9 [2] a1 a4 [2] a3 a5 [2] b8 a3 [2] a4 a4 [2] b8 8b }

  condition:
    any of them
}