rule TTP_XOR_QUAD_CurrentVersionRun_e28f {
  strings:
    $key_e28f = { b1 e0 [2] 95 ee [2] be c2 [2] 90 e0 [2] 84 fb [2] 8b e1 [2] 95 fc [2] 97 fd [2] 8c fb [2] 90 fc [2] 8c d3 }

  condition:
    any of them
}