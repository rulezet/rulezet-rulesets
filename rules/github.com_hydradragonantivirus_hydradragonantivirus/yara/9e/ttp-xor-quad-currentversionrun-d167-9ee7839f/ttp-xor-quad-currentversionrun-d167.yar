rule TTP_XOR_QUAD_CurrentVersionRun_d167 {
  strings:
    $key_d167 = { 82 08 [2] a6 06 [2] 8d 2a [2] a3 08 [2] b7 13 [2] b8 09 [2] a6 14 [2] a4 15 [2] bf 13 [2] a3 14 [2] bf 3b }

  condition:
    any of them
}