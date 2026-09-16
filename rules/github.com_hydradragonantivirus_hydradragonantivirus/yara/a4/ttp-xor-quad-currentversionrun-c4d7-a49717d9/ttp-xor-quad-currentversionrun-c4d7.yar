rule TTP_XOR_QUAD_CurrentVersionRun_c4d7 {
  strings:
    $key_c4d7 = { 97 b8 [2] b3 b6 [2] 98 9a [2] b6 b8 [2] a2 a3 [2] ad b9 [2] b3 a4 [2] b1 a5 [2] aa a3 [2] b6 a4 [2] aa 8b }

  condition:
    any of them
}