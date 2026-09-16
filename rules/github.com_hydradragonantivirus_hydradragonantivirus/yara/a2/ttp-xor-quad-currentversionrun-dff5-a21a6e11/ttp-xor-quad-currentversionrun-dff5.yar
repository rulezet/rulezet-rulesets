rule TTP_XOR_QUAD_CurrentVersionRun_dff5 {
  strings:
    $key_dff5 = { 8c 9a [2] a8 94 [2] 83 b8 [2] ad 9a [2] b9 81 [2] b6 9b [2] a8 86 [2] aa 87 [2] b1 81 [2] ad 86 [2] b1 a9 }

  condition:
    any of them
}