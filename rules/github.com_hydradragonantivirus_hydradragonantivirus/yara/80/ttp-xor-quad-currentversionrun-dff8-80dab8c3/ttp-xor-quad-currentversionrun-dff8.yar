rule TTP_XOR_QUAD_CurrentVersionRun_dff8 {
  strings:
    $key_dff8 = { 8c 97 [2] a8 99 [2] 83 b5 [2] ad 97 [2] b9 8c [2] b6 96 [2] a8 8b [2] aa 8a [2] b1 8c [2] ad 8b [2] b1 a4 }

  condition:
    any of them
}