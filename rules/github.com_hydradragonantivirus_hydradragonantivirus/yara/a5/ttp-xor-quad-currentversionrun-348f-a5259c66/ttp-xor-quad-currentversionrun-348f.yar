rule TTP_XOR_QUAD_CurrentVersionRun_348f {
  strings:
    $key_348f = { 67 e0 [2] 43 ee [2] 68 c2 [2] 46 e0 [2] 52 fb [2] 5d e1 [2] 43 fc [2] 41 fd [2] 5a fb [2] 46 fc [2] 5a d3 }

  condition:
    any of them
}