rule TTP_XOR_QUAD_CurrentVersionRun_d1c7 {
  strings:
    $key_d1c7 = { 82 a8 [2] a6 a6 [2] 8d 8a [2] a3 a8 [2] b7 b3 [2] b8 a9 [2] a6 b4 [2] a4 b5 [2] bf b3 [2] a3 b4 [2] bf 9b }

  condition:
    any of them
}