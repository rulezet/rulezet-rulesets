rule TTP_XOR_QUAD_CurrentVersionRun_d1fa {
  strings:
    $key_d1fa = { 82 95 [2] a6 9b [2] 8d b7 [2] a3 95 [2] b7 8e [2] b8 94 [2] a6 89 [2] a4 88 [2] bf 8e [2] a3 89 [2] bf a6 }

  condition:
    any of them
}