rule TTP_XOR_QUAD_CurrentVersionRun_d137 {
  strings:
    $key_d137 = { 82 58 [2] a6 56 [2] 8d 7a [2] a3 58 [2] b7 43 [2] b8 59 [2] a6 44 [2] a4 45 [2] bf 43 [2] a3 44 [2] bf 6b }

  condition:
    any of them
}