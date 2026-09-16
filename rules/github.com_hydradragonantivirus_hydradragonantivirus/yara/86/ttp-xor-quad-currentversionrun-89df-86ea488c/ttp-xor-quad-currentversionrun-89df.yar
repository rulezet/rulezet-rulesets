rule TTP_XOR_QUAD_CurrentVersionRun_89df {
  strings:
    $key_89df = { da b0 [2] fe be [2] d5 92 [2] fb b0 [2] ef ab [2] e0 b1 [2] fe ac [2] fc ad [2] e7 ab [2] fb ac [2] e7 83 }

  condition:
    any of them
}