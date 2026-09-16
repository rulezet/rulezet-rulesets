rule TTP_XOR_QUAD_CurrentVersionRun_cf8f {
  strings:
    $key_cf8f = { 9c e0 [2] b8 ee [2] 93 c2 [2] bd e0 [2] a9 fb [2] a6 e1 [2] b8 fc [2] ba fd [2] a1 fb [2] bd fc [2] a1 d3 }

  condition:
    any of them
}