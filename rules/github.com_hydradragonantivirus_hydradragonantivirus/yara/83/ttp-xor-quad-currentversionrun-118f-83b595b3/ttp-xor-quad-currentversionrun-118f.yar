rule TTP_XOR_QUAD_CurrentVersionRun_118f {
  strings:
    $key_118f = { 42 e0 [2] 66 ee [2] 4d c2 [2] 63 e0 [2] 77 fb [2] 78 e1 [2] 66 fc [2] 64 fd [2] 7f fb [2] 63 fc [2] 7f d3 }

  condition:
    any of them
}