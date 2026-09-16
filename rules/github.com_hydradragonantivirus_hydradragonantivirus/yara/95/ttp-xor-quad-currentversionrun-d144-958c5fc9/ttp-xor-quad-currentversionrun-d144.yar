rule TTP_XOR_QUAD_CurrentVersionRun_d144 {
  strings:
    $key_d144 = { 82 2b [2] a6 25 [2] 8d 09 [2] a3 2b [2] b7 30 [2] b8 2a [2] a6 37 [2] a4 36 [2] bf 30 [2] a3 37 [2] bf 18 }

  condition:
    any of them
}