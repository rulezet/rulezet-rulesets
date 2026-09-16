rule TTP_XOR_QUAD_CurrentVersionRun_328f {
  strings:
    $key_328f = { 61 e0 [2] 45 ee [2] 6e c2 [2] 40 e0 [2] 54 fb [2] 5b e1 [2] 45 fc [2] 47 fd [2] 5c fb [2] 40 fc [2] 5c d3 }

  condition:
    any of them
}