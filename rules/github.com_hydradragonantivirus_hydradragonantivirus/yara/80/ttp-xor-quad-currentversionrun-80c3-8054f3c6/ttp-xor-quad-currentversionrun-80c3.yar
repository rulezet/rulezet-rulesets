rule TTP_XOR_QUAD_CurrentVersionRun_80c3 {
  strings:
    $key_80c3 = { d3 ac [2] f7 a2 [2] dc 8e [2] f2 ac [2] e6 b7 [2] e9 ad [2] f7 b0 [2] f5 b1 [2] ee b7 [2] f2 b0 [2] ee 9f }

  condition:
    any of them
}