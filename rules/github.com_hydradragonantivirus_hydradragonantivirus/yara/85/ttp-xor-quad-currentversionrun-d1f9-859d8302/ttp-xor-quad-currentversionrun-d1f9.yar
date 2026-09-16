rule TTP_XOR_QUAD_CurrentVersionRun_d1f9 {
  strings:
    $key_d1f9 = { 82 96 [2] a6 98 [2] 8d b4 [2] a3 96 [2] b7 8d [2] b8 97 [2] a6 8a [2] a4 8b [2] bf 8d [2] a3 8a [2] bf a5 }

  condition:
    any of them
}