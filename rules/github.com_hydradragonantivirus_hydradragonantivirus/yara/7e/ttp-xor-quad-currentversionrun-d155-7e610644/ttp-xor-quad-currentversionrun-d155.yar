rule TTP_XOR_QUAD_CurrentVersionRun_d155 {
  strings:
    $key_d155 = { 82 3a [2] a6 34 [2] 8d 18 [2] a3 3a [2] b7 21 [2] b8 3b [2] a6 26 [2] a4 27 [2] bf 21 [2] a3 26 [2] bf 09 }

  condition:
    any of them
}