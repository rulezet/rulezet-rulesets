rule TTP_XOR_QUAD_CurrentVersionRun_d675 {
  strings:
    $key_d675 = { 85 1a [2] a1 14 [2] 8a 38 [2] a4 1a [2] b0 01 [2] bf 1b [2] a1 06 [2] a3 07 [2] b8 01 [2] a4 06 [2] b8 29 }

  condition:
    any of them
}