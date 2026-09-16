rule TTP_XOR_QUAD_CurrentVersionRun_d6e5 {
  strings:
    $key_d6e5 = { 85 8a [2] a1 84 [2] 8a a8 [2] a4 8a [2] b0 91 [2] bf 8b [2] a1 96 [2] a3 97 [2] b8 91 [2] a4 96 [2] b8 b9 }

  condition:
    any of them
}