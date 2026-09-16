rule TTP_XOR_QUAD_CurrentVersionRun_d08f {
  strings:
    $key_d08f = { 83 e0 [2] a7 ee [2] 8c c2 [2] a2 e0 [2] b6 fb [2] b9 e1 [2] a7 fc [2] a5 fd [2] be fb [2] a2 fc [2] be d3 }

  condition:
    any of them
}