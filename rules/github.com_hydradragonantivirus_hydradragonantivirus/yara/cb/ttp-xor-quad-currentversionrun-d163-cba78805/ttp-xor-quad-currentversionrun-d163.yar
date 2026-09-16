rule TTP_XOR_QUAD_CurrentVersionRun_d163 {
  strings:
    $key_d163 = { 82 0c [2] a6 02 [2] 8d 2e [2] a3 0c [2] b7 17 [2] b8 0d [2] a6 10 [2] a4 11 [2] bf 17 [2] a3 10 [2] bf 3f }

  condition:
    any of them
}