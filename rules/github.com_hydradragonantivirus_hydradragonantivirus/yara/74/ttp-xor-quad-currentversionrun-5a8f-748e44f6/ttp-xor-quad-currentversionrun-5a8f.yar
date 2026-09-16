rule TTP_XOR_QUAD_CurrentVersionRun_5a8f {
  strings:
    $key_5a8f = { 09 e0 [2] 2d ee [2] 06 c2 [2] 28 e0 [2] 3c fb [2] 33 e1 [2] 2d fc [2] 2f fd [2] 34 fb [2] 28 fc [2] 34 d3 }

  condition:
    any of them
}