rule TTP_XOR_QUAD_CurrentVersionRun_ce9d {
  strings:
    $key_ce9d = { 9d f2 [2] b9 fc [2] 92 d0 [2] bc f2 [2] a8 e9 [2] a7 f3 [2] b9 ee [2] bb ef [2] a0 e9 [2] bc ee [2] a0 c1 }

  condition:
    any of them
}