rule TTP_XOR_QUAD_CurrentVersionRun_028f {
  strings:
    $key_028f = { 51 e0 [2] 75 ee [2] 5e c2 [2] 70 e0 [2] 64 fb [2] 6b e1 [2] 75 fc [2] 77 fd [2] 6c fb [2] 70 fc [2] 6c d3 }

  condition:
    any of them
}