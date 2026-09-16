rule TTP_XOR_QUAD_CurrentVersionRun_638f {
  strings:
    $key_638f = { 30 e0 [2] 14 ee [2] 3f c2 [2] 11 e0 [2] 05 fb [2] 0a e1 [2] 14 fc [2] 16 fd [2] 0d fb [2] 11 fc [2] 0d d3 }

  condition:
    any of them
}