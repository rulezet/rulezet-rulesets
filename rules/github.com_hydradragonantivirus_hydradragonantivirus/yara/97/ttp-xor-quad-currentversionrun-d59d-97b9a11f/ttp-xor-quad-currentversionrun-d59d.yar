rule TTP_XOR_QUAD_CurrentVersionRun_d59d {
  strings:
    $key_d59d = { 86 f2 [2] a2 fc [2] 89 d0 [2] a7 f2 [2] b3 e9 [2] bc f3 [2] a2 ee [2] a0 ef [2] bb e9 [2] a7 ee [2] bb c1 }

  condition:
    any of them
}