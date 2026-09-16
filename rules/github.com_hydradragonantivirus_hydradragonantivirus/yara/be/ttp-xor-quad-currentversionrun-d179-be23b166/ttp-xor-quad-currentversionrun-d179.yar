rule TTP_XOR_QUAD_CurrentVersionRun_d179 {
  strings:
    $key_d179 = { 82 16 [2] a6 18 [2] 8d 34 [2] a3 16 [2] b7 0d [2] b8 17 [2] a6 0a [2] a4 0b [2] bf 0d [2] a3 0a [2] bf 25 }

  condition:
    any of them
}