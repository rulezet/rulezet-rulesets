rule TTP_XOR_QUAD_CurrentVersionRun_d667 {
  strings:
    $key_d667 = { 85 08 [2] a1 06 [2] 8a 2a [2] a4 08 [2] b0 13 [2] bf 09 [2] a1 14 [2] a3 15 [2] b8 13 [2] a4 14 [2] b8 3b }

  condition:
    any of them
}