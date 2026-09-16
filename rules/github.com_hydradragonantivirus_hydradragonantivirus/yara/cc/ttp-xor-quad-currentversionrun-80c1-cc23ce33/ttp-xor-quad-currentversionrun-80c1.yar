rule TTP_XOR_QUAD_CurrentVersionRun_80c1 {
  strings:
    $key_80c1 = { d3 ae [2] f7 a0 [2] dc 8c [2] f2 ae [2] e6 b5 [2] e9 af [2] f7 b2 [2] f5 b3 [2] ee b5 [2] f2 b2 [2] ee 9d }

  condition:
    any of them
}