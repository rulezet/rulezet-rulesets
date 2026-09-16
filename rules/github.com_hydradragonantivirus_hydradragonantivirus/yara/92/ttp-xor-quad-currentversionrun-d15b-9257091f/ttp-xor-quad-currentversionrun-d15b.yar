rule TTP_XOR_QUAD_CurrentVersionRun_d15b {
  strings:
    $key_d15b = { 82 34 [2] a6 3a [2] 8d 16 [2] a3 34 [2] b7 2f [2] b8 35 [2] a6 28 [2] a4 29 [2] bf 2f [2] a3 28 [2] bf 07 }

  condition:
    any of them
}