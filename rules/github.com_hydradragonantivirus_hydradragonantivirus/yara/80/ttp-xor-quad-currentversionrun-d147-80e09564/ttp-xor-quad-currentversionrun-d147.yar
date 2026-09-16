rule TTP_XOR_QUAD_CurrentVersionRun_d147 {
  strings:
    $key_d147 = { 82 28 [2] a6 26 [2] 8d 0a [2] a3 28 [2] b7 33 [2] b8 29 [2] a6 34 [2] a4 35 [2] bf 33 [2] a3 34 [2] bf 1b }

  condition:
    any of them
}