rule TTP_XOR_QUAD_CurrentVersionRun_c6e9 {
  strings:
    $key_c6e9 = { 95 86 [2] b1 88 [2] 9a a4 [2] b4 86 [2] a0 9d [2] af 87 [2] b1 9a [2] b3 9b [2] a8 9d [2] b4 9a [2] a8 b5 }

  condition:
    any of them
}