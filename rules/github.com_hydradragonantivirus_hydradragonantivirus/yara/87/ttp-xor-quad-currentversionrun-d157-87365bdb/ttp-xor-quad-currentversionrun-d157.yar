rule TTP_XOR_QUAD_CurrentVersionRun_d157 {
  strings:
    $key_d157 = { 82 38 [2] a6 36 [2] 8d 1a [2] a3 38 [2] b7 23 [2] b8 39 [2] a6 24 [2] a4 25 [2] bf 23 [2] a3 24 [2] bf 0b }

  condition:
    any of them
}