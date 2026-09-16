rule TTP_XOR_QUAD_CurrentVersionRun_de8f {
  strings:
    $key_de8f = { 8d e0 [2] a9 ee [2] 82 c2 [2] ac e0 [2] b8 fb [2] b7 e1 [2] a9 fc [2] ab fd [2] b0 fb [2] ac fc [2] b0 d3 }

  condition:
    any of them
}