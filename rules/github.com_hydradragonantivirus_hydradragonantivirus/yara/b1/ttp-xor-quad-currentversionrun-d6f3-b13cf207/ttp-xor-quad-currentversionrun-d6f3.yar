rule TTP_XOR_QUAD_CurrentVersionRun_d6f3 {
  strings:
    $key_d6f3 = { 85 9c [2] a1 92 [2] 8a be [2] a4 9c [2] b0 87 [2] bf 9d [2] a1 80 [2] a3 81 [2] b8 87 [2] a4 80 [2] b8 af }

  condition:
    any of them
}