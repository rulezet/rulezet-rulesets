rule TTP_XOR_QUAD_CurrentVersionRun_80df {
  strings:
    $key_80df = { d3 b0 [2] f7 be [2] dc 92 [2] f2 b0 [2] e6 ab [2] e9 b1 [2] f7 ac [2] f5 ad [2] ee ab [2] f2 ac [2] ee 83 }

  condition:
    any of them
}