rule TTP_XOR_QUAD_CurrentVersionRun_c4f8 {
  strings:
    $key_c4f8 = { 97 97 [2] b3 99 [2] 98 b5 [2] b6 97 [2] a2 8c [2] ad 96 [2] b3 8b [2] b1 8a [2] aa 8c [2] b6 8b [2] aa a4 }

  condition:
    any of them
}