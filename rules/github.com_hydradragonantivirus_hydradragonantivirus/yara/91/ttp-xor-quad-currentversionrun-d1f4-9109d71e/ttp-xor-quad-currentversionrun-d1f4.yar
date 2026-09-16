rule TTP_XOR_QUAD_CurrentVersionRun_d1f4 {
  strings:
    $key_d1f4 = { 82 9b [2] a6 95 [2] 8d b9 [2] a3 9b [2] b7 80 [2] b8 9a [2] a6 87 [2] a4 86 [2] bf 80 [2] a3 87 [2] bf a8 }

  condition:
    any of them
}