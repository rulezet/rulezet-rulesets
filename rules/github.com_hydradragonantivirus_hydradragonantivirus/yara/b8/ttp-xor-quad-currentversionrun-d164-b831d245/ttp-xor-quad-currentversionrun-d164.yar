rule TTP_XOR_QUAD_CurrentVersionRun_d164 {
  strings:
    $key_d164 = { 82 0b [2] a6 05 [2] 8d 29 [2] a3 0b [2] b7 10 [2] b8 0a [2] a6 17 [2] a4 16 [2] bf 10 [2] a3 17 [2] bf 38 }

  condition:
    any of them
}