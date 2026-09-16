rule TTP_XOR_QUAD_CurrentVersionRun_628f {
  strings:
    $key_628f = { 31 e0 [2] 15 ee [2] 3e c2 [2] 10 e0 [2] 04 fb [2] 0b e1 [2] 15 fc [2] 17 fd [2] 0c fb [2] 10 fc [2] 0c d3 }

  condition:
    any of them
}