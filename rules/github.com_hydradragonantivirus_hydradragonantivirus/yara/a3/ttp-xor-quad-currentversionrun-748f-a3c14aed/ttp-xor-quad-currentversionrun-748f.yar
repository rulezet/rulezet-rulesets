rule TTP_XOR_QUAD_CurrentVersionRun_748f {
  strings:
    $key_748f = { 27 e0 [2] 03 ee [2] 28 c2 [2] 06 e0 [2] 12 fb [2] 1d e1 [2] 03 fc [2] 01 fd [2] 1a fb [2] 06 fc [2] 1a d3 }

  condition:
    any of them
}