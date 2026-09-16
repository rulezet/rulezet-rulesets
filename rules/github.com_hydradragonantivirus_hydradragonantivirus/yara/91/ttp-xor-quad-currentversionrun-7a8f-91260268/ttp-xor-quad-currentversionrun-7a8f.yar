rule TTP_XOR_QUAD_CurrentVersionRun_7a8f {
  strings:
    $key_7a8f = { 29 e0 [2] 0d ee [2] 26 c2 [2] 08 e0 [2] 1c fb [2] 13 e1 [2] 0d fc [2] 0f fd [2] 14 fb [2] 08 fc [2] 14 d3 }

  condition:
    any of them
}