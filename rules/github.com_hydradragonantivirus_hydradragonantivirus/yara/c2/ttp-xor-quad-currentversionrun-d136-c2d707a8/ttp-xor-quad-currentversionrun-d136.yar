rule TTP_XOR_QUAD_CurrentVersionRun_d136 {
  strings:
    $key_d136 = { 82 59 [2] a6 57 [2] 8d 7b [2] a3 59 [2] b7 42 [2] b8 58 [2] a6 45 [2] a4 44 [2] bf 42 [2] a3 45 [2] bf 6a }

  condition:
    any of them
}