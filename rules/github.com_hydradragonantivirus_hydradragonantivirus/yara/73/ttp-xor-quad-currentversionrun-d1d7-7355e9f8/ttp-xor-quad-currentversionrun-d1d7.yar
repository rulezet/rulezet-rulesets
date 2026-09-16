rule TTP_XOR_QUAD_CurrentVersionRun_d1d7 {
  strings:
    $key_d1d7 = { 82 b8 [2] a6 b6 [2] 8d 9a [2] a3 b8 [2] b7 a3 [2] b8 b9 [2] a6 a4 [2] a4 a5 [2] bf a3 [2] a3 a4 [2] bf 8b }

  condition:
    any of them
}