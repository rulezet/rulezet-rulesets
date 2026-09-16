rule TTP_XOR_QUAD_CurrentVersionRun_158f {
  strings:
    $key_158f = { 46 e0 [2] 62 ee [2] 49 c2 [2] 67 e0 [2] 73 fb [2] 7c e1 [2] 62 fc [2] 60 fd [2] 7b fb [2] 67 fc [2] 7b d3 }

  condition:
    any of them
}