rule TTP_XOR_QUAD_CurrentVersionRun_80c2 {
  strings:
    $key_80c2 = { d3 ad [2] f7 a3 [2] dc 8f [2] f2 ad [2] e6 b6 [2] e9 ac [2] f7 b1 [2] f5 b0 [2] ee b6 [2] f2 b1 [2] ee 9e }

  condition:
    any of them
}