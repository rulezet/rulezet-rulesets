rule TTP_XOR_QUAD_CurrentVersionRun_d6b3 {
  strings:
    $key_d6b3 = { 85 dc [2] a1 d2 [2] 8a fe [2] a4 dc [2] b0 c7 [2] bf dd [2] a1 c0 [2] a3 c1 [2] b8 c7 [2] a4 c0 [2] b8 ef }

  condition:
    any of them
}