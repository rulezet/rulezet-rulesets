rule TTP_XOR_QUAD_CurrentVersionRun_d6e4 {
  strings:
    $key_d6e4 = { 85 8b [2] a1 85 [2] 8a a9 [2] a4 8b [2] b0 90 [2] bf 8a [2] a1 97 [2] a3 96 [2] b8 90 [2] a4 97 [2] b8 b8 }

  condition:
    any of them
}