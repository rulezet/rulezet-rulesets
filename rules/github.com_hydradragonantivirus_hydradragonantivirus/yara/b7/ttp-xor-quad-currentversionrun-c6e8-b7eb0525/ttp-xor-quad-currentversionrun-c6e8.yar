rule TTP_XOR_QUAD_CurrentVersionRun_c6e8 {
  strings:
    $key_c6e8 = { 95 87 [2] b1 89 [2] 9a a5 [2] b4 87 [2] a0 9c [2] af 86 [2] b1 9b [2] b3 9a [2] a8 9c [2] b4 9b [2] a8 b4 }

  condition:
    any of them
}