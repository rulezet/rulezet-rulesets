rule TTP_XOR_QUAD_CurrentVersionRun_2f8f {
  strings:
    $key_2f8f = { 7c e0 [2] 58 ee [2] 73 c2 [2] 5d e0 [2] 49 fb [2] 46 e1 [2] 58 fc [2] 5a fd [2] 41 fb [2] 5d fc [2] 41 d3 }

  condition:
    any of them
}