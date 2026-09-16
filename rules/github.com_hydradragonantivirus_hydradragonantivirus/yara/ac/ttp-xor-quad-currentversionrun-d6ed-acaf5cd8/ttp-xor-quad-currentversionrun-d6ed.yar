rule TTP_XOR_QUAD_CurrentVersionRun_d6ed {
  strings:
    $key_d6ed = { 85 82 [2] a1 8c [2] 8a a0 [2] a4 82 [2] b0 99 [2] bf 83 [2] a1 9e [2] a3 9f [2] b8 99 [2] a4 9e [2] b8 b1 }

  condition:
    any of them
}