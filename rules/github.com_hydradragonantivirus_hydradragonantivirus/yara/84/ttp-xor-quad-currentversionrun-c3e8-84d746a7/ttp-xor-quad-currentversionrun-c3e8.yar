rule TTP_XOR_QUAD_CurrentVersionRun_c3e8 {
  strings:
    $key_c3e8 = { 90 87 [2] b4 89 [2] 9f a5 [2] b1 87 [2] a5 9c [2] aa 86 [2] b4 9b [2] b6 9a [2] ad 9c [2] b1 9b [2] ad b4 }

  condition:
    any of them
}