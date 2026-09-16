rule TTP_XOR_QUAD_CurrentVersionRun_128f {
  strings:
    $key_128f = { 41 e0 [2] 65 ee [2] 4e c2 [2] 60 e0 [2] 74 fb [2] 7b e1 [2] 65 fc [2] 67 fd [2] 7c fb [2] 60 fc [2] 7c d3 }

  condition:
    any of them
}