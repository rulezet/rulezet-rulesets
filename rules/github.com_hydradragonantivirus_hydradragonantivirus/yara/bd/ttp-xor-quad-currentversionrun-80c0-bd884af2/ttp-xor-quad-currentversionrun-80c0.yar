rule TTP_XOR_QUAD_CurrentVersionRun_80c0 {
  strings:
    $key_80c0 = { d3 af [2] f7 a1 [2] dc 8d [2] f2 af [2] e6 b4 [2] e9 ae [2] f7 b3 [2] f5 b2 [2] ee b4 [2] f2 b3 [2] ee 9c }

  condition:
    any of them
}