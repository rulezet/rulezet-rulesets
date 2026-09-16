rule TTP_XOR_QUAD_CurrentVersionRun_c7f4 {
  strings:
    $key_c7f4 = { 94 9b [2] b0 95 [2] 9b b9 [2] b5 9b [2] a1 80 [2] ae 9a [2] b0 87 [2] b2 86 [2] a9 80 [2] b5 87 [2] a9 a8 }

  condition:
    any of them
}