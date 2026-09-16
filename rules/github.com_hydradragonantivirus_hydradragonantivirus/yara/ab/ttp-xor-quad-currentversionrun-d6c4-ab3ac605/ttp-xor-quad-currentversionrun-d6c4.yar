rule TTP_XOR_QUAD_CurrentVersionRun_d6c4 {
  strings:
    $key_d6c4 = { 85 ab [2] a1 a5 [2] 8a 89 [2] a4 ab [2] b0 b0 [2] bf aa [2] a1 b7 [2] a3 b6 [2] b8 b0 [2] a4 b7 [2] b8 98 }

  condition:
    any of them
}