rule TTP_XOR_QUAD_CurrentVersionRun_8cdf {
  strings:
    $key_8cdf = { df b0 [2] fb be [2] d0 92 [2] fe b0 [2] ea ab [2] e5 b1 [2] fb ac [2] f9 ad [2] e2 ab [2] fe ac [2] e2 83 }

  condition:
    any of them
}