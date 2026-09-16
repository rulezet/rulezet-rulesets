rule TTP_XOR_QUAD_CurrentVersionRun_d623 {
  strings:
    $key_d623 = { 85 4c [2] a1 42 [2] 8a 6e [2] a4 4c [2] b0 57 [2] bf 4d [2] a1 50 [2] a3 51 [2] b8 57 [2] a4 50 [2] b8 7f }

  condition:
    any of them
}