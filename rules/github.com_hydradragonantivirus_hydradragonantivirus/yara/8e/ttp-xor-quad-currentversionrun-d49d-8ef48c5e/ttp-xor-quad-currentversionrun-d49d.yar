rule TTP_XOR_QUAD_CurrentVersionRun_d49d {
  strings:
    $key_d49d = { 87 f2 [2] a3 fc [2] 88 d0 [2] a6 f2 [2] b2 e9 [2] bd f3 [2] a3 ee [2] a1 ef [2] ba e9 [2] a6 ee [2] ba c1 }

  condition:
    any of them
}