rule TTP_XOR_QUAD_CurrentVersionRun_c38f {
  strings:
    $key_c38f = { 90 e0 [2] b4 ee [2] 9f c2 [2] b1 e0 [2] a5 fb [2] aa e1 [2] b4 fc [2] b6 fd [2] ad fb [2] b1 fc [2] ad d3 }

  condition:
    any of them
}