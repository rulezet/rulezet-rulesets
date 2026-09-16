rule TTP_XOR_QUAD_CurrentVersionRun_80d8 {
  strings:
    $key_80d8 = { d3 b7 [2] f7 b9 [2] dc 95 [2] f2 b7 [2] e6 ac [2] e9 b6 [2] f7 ab [2] f5 aa [2] ee ac [2] f2 ab [2] ee 84 }

  condition:
    any of them
}