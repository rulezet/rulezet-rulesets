rule TTP_XOR_QUAD_CurrentVersionRun_668f {
  strings:
    $key_668f = { 35 e0 [2] 11 ee [2] 3a c2 [2] 14 e0 [2] 00 fb [2] 0f e1 [2] 11 fc [2] 13 fd [2] 08 fb [2] 14 fc [2] 08 d3 }

  condition:
    any of them
}