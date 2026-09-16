rule TTP_XOR_QUAD_CurrentVersionRun_548f {
  strings:
    $key_548f = { 07 e0 [2] 23 ee [2] 08 c2 [2] 26 e0 [2] 32 fb [2] 3d e1 [2] 23 fc [2] 21 fd [2] 3a fb [2] 26 fc [2] 3a d3 }

  condition:
    any of them
}