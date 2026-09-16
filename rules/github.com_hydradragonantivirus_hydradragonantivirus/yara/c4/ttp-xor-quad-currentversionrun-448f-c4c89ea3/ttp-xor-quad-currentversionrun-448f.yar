rule TTP_XOR_QUAD_CurrentVersionRun_448f {
  strings:
    $key_448f = { 17 e0 [2] 33 ee [2] 18 c2 [2] 36 e0 [2] 22 fb [2] 2d e1 [2] 33 fc [2] 31 fd [2] 2a fb [2] 36 fc [2] 2a d3 }

  condition:
    any of them
}