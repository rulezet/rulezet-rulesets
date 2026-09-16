rule TTP_XOR_QUAD_CurrentVersionRun_338f {
  strings:
    $key_338f = { 60 e0 [2] 44 ee [2] 6f c2 [2] 41 e0 [2] 55 fb [2] 5a e1 [2] 44 fc [2] 46 fd [2] 5d fb [2] 41 fc [2] 5d d3 }

  condition:
    any of them
}