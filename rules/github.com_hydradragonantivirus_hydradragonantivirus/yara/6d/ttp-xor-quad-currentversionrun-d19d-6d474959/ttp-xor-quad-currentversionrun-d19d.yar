rule TTP_XOR_QUAD_CurrentVersionRun_d19d {
  strings:
    $key_d19d = { 82 f2 [2] a6 fc [2] 8d d0 [2] a3 f2 [2] b7 e9 [2] b8 f3 [2] a6 ee [2] a4 ef [2] bf e9 [2] a3 ee [2] bf c1 }

  condition:
    any of them
}