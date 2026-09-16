rule TTP_XOR_QUAD_CurrentVersionRun_438f {
  strings:
    $key_438f = { 10 e0 [2] 34 ee [2] 1f c2 [2] 31 e0 [2] 25 fb [2] 2a e1 [2] 34 fc [2] 36 fd [2] 2d fb [2] 31 fc [2] 2d d3 }

  condition:
    any of them
}