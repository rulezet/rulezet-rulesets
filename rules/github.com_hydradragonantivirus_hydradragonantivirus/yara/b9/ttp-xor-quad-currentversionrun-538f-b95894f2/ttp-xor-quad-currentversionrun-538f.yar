rule TTP_XOR_QUAD_CurrentVersionRun_538f {
  strings:
    $key_538f = { 00 e0 [2] 24 ee [2] 0f c2 [2] 21 e0 [2] 35 fb [2] 3a e1 [2] 24 fc [2] 26 fd [2] 3d fb [2] 21 fc [2] 3d d3 }

  condition:
    any of them
}