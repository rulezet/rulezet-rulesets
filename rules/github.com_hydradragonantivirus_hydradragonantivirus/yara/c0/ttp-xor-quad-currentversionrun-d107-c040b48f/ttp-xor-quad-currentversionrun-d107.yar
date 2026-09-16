rule TTP_XOR_QUAD_CurrentVersionRun_d107 {
  strings:
    $key_d107 = { 82 68 [2] a6 66 [2] 8d 4a [2] a3 68 [2] b7 73 [2] b8 69 [2] a6 74 [2] a4 75 [2] bf 73 [2] a3 74 [2] bf 5b }

  condition:
    any of them
}