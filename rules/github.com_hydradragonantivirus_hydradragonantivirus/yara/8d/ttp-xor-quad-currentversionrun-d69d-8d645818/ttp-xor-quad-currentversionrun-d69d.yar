rule TTP_XOR_QUAD_CurrentVersionRun_d69d {
  strings:
    $key_d69d = { 85 f2 [2] a1 fc [2] 8a d0 [2] a4 f2 [2] b0 e9 [2] bf f3 [2] a1 ee [2] a3 ef [2] b8 e9 [2] a4 ee [2] b8 c1 }

  condition:
    any of them
}