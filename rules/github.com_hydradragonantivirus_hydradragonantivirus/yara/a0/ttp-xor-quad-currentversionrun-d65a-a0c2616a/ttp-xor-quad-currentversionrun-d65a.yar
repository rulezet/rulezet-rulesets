rule TTP_XOR_QUAD_CurrentVersionRun_d65a {
  strings:
    $key_d65a = { 85 35 [2] a1 3b [2] 8a 17 [2] a4 35 [2] b0 2e [2] bf 34 [2] a1 29 [2] a3 28 [2] b8 2e [2] a4 29 [2] b8 06 }

  condition:
    any of them
}