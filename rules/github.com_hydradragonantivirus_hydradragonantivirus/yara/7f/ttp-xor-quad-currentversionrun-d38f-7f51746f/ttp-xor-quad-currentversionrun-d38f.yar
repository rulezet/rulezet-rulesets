rule TTP_XOR_QUAD_CurrentVersionRun_d38f {
  strings:
    $key_d38f = { 80 e0 [2] a4 ee [2] 8f c2 [2] a1 e0 [2] b5 fb [2] ba e1 [2] a4 fc [2] a6 fd [2] bd fb [2] a1 fc [2] bd d3 }

  condition:
    any of them
}