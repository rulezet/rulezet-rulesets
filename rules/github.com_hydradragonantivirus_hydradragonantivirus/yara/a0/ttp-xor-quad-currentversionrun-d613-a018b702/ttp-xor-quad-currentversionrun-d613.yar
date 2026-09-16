rule TTP_XOR_QUAD_CurrentVersionRun_d613 {
  strings:
    $key_d613 = { 85 7c [2] a1 72 [2] 8a 5e [2] a4 7c [2] b0 67 [2] bf 7d [2] a1 60 [2] a3 61 [2] b8 67 [2] a4 60 [2] b8 4f }

  condition:
    any of them
}