rule TTP_XOR_QUAD_CurrentVersionRun_768f {
  strings:
    $key_768f = { 25 e0 [2] 01 ee [2] 2a c2 [2] 04 e0 [2] 10 fb [2] 1f e1 [2] 01 fc [2] 03 fd [2] 18 fb [2] 04 fc [2] 18 d3 }

  condition:
    any of them
}