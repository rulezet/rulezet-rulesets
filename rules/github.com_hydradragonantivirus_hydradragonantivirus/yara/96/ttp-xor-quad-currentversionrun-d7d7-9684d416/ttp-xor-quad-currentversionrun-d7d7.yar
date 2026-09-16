rule TTP_XOR_QUAD_CurrentVersionRun_d7d7 {
  strings:
    $key_d7d7 = { 84 b8 [2] a0 b6 [2] 8b 9a [2] a5 b8 [2] b1 a3 [2] be b9 [2] a0 a4 [2] a2 a5 [2] b9 a3 [2] a5 a4 [2] b9 8b }

  condition:
    any of them
}