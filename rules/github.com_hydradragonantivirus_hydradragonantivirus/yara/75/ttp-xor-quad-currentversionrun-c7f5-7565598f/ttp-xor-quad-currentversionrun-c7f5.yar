rule TTP_XOR_QUAD_CurrentVersionRun_c7f5 {
  strings:
    $key_c7f5 = { 94 9a [2] b0 94 [2] 9b b8 [2] b5 9a [2] a1 81 [2] ae 9b [2] b0 86 [2] b2 87 [2] a9 81 [2] b5 86 [2] a9 a9 }

  condition:
    any of them
}