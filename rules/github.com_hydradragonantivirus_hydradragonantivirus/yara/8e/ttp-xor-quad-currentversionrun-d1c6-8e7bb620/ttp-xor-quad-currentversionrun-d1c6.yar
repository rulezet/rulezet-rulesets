rule TTP_XOR_QUAD_CurrentVersionRun_d1c6 {
  strings:
    $key_d1c6 = { 82 a9 [2] a6 a7 [2] 8d 8b [2] a3 a9 [2] b7 b2 [2] b8 a8 [2] a6 b5 [2] a4 b4 [2] bf b2 [2] a3 b5 [2] bf 9a }

  condition:
    any of them
}