rule TTP_XOR_QUAD_CurrentVersionRun_038f {
  strings:
    $key_038f = { 50 e0 [2] 74 ee [2] 5f c2 [2] 71 e0 [2] 65 fb [2] 6a e1 [2] 74 fc [2] 76 fd [2] 6d fb [2] 71 fc [2] 6d d3 }

  condition:
    any of them
}