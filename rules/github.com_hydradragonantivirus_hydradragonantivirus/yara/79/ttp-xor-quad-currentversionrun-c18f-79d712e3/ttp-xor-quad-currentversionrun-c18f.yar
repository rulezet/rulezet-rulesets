rule TTP_XOR_QUAD_CurrentVersionRun_c18f {
  strings:
    $key_c18f = { 92 e0 [2] b6 ee [2] 9d c2 [2] b3 e0 [2] a7 fb [2] a8 e1 [2] b6 fc [2] b4 fd [2] af fb [2] b3 fc [2] af d3 }

  condition:
    any of them
}