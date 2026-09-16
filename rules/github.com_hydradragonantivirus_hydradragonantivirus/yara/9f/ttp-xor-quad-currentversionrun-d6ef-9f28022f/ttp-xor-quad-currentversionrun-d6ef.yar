rule TTP_XOR_QUAD_CurrentVersionRun_d6ef {
  strings:
    $key_d6ef = { 85 80 [2] a1 8e [2] 8a a2 [2] a4 80 [2] b0 9b [2] bf 81 [2] a1 9c [2] a3 9d [2] b8 9b [2] a4 9c [2] b8 b3 }

  condition:
    any of them
}