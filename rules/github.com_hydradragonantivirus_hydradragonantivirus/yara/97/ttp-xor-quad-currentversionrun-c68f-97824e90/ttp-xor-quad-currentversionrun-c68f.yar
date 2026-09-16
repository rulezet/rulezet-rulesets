rule TTP_XOR_QUAD_CurrentVersionRun_c68f {
  strings:
    $key_c68f = { 95 e0 [2] b1 ee [2] 9a c2 [2] b4 e0 [2] a0 fb [2] af e1 [2] b1 fc [2] b3 fd [2] a8 fb [2] b4 fc [2] a8 d3 }

  condition:
    any of them
}