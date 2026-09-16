rule TTP_XOR_QUAD_CurrentVersionRun_418f {
  strings:
    $key_418f = { 12 e0 [2] 36 ee [2] 1d c2 [2] 33 e0 [2] 27 fb [2] 28 e1 [2] 36 fc [2] 34 fd [2] 2f fb [2] 33 fc [2] 2f d3 }

  condition:
    any of them
}