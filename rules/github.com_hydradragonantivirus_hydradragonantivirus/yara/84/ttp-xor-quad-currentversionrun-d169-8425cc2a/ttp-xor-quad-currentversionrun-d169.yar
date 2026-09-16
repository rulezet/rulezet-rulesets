rule TTP_XOR_QUAD_CurrentVersionRun_d169 {
  strings:
    $key_d169 = { 82 06 [2] a6 08 [2] 8d 24 [2] a3 06 [2] b7 1d [2] b8 07 [2] a6 1a [2] a4 1b [2] bf 1d [2] a3 1a [2] bf 35 }

  condition:
    any of them
}