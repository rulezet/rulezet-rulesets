rule TTP_XOR_QUAD_CurrentVersionRun_d180 {
  strings:
    $key_d180 = { 82 ef [2] a6 e1 [2] 8d cd [2] a3 ef [2] b7 f4 [2] b8 ee [2] a6 f3 [2] a4 f2 [2] bf f4 [2] a3 f3 [2] bf dc }

  condition:
    any of them
}