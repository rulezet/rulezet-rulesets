rule TTP_XOR_QUAD_CurrentVersionRun_c3f5 {
  strings:
    $key_c3f5 = { 90 9a [2] b4 94 [2] 9f b8 [2] b1 9a [2] a5 81 [2] aa 9b [2] b4 86 [2] b6 87 [2] ad 81 [2] b1 86 [2] ad a9 }

  condition:
    any of them
}