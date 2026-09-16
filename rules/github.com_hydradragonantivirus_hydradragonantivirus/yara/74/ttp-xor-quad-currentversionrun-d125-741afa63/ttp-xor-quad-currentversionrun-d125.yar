rule TTP_XOR_QUAD_CurrentVersionRun_d125 {
  strings:
    $key_d125 = { 82 4a [2] a6 44 [2] 8d 68 [2] a3 4a [2] b7 51 [2] b8 4b [2] a6 56 [2] a4 57 [2] bf 51 [2] a3 56 [2] bf 79 }

  condition:
    any of them
}