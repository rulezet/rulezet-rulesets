rule TTP_XOR_QUAD_CurrentVersionRun_d173 {
  strings:
    $key_d173 = { 82 1c [2] a6 12 [2] 8d 3e [2] a3 1c [2] b7 07 [2] b8 1d [2] a6 00 [2] a4 01 [2] bf 07 [2] a3 00 [2] bf 2f }

  condition:
    any of them
}