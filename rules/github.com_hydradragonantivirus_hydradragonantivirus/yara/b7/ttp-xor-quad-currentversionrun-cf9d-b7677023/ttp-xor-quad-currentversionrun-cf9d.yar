rule TTP_XOR_QUAD_CurrentVersionRun_cf9d {
  strings:
    $key_cf9d = { 9c f2 [2] b8 fc [2] 93 d0 [2] bd f2 [2] a9 e9 [2] a6 f3 [2] b8 ee [2] ba ef [2] a1 e9 [2] bd ee [2] a1 c1 }

  condition:
    any of them
}