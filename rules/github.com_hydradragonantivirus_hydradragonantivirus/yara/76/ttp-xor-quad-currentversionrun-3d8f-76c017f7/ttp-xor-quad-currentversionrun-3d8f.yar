rule TTP_XOR_QUAD_CurrentVersionRun_3d8f {
  strings:
    $key_3d8f = { 6e e0 [2] 4a ee [2] 61 c2 [2] 4f e0 [2] 5b fb [2] 54 e1 [2] 4a fc [2] 48 fd [2] 53 fb [2] 4f fc [2] 53 d3 }

  condition:
    any of them
}