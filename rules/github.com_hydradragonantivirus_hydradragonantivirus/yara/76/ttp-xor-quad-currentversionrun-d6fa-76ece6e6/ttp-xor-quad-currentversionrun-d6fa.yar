rule TTP_XOR_QUAD_CurrentVersionRun_d6fa {
  strings:
    $key_d6fa = { 85 95 [2] a1 9b [2] 8a b7 [2] a4 95 [2] b0 8e [2] bf 94 [2] a1 89 [2] a3 88 [2] b8 8e [2] a4 89 [2] b8 a6 }

  condition:
    any of them
}