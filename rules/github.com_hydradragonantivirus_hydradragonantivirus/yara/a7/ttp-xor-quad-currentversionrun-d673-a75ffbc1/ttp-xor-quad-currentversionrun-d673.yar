rule TTP_XOR_QUAD_CurrentVersionRun_d673 {
  strings:
    $key_d673 = { 85 1c [2] a1 12 [2] 8a 3e [2] a4 1c [2] b0 07 [2] bf 1d [2] a1 00 [2] a3 01 [2] b8 07 [2] a4 00 [2] b8 2f }

  condition:
    any of them
}