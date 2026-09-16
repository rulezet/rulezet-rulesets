rule TTP_XOR_QUAD_CurrentVersionRun_d6f5 {
  strings:
    $key_d6f5 = { 85 9a [2] a1 94 [2] 8a b8 [2] a4 9a [2] b0 81 [2] bf 9b [2] a1 86 [2] a3 87 [2] b8 81 [2] a4 86 [2] b8 a9 }

  condition:
    any of them
}