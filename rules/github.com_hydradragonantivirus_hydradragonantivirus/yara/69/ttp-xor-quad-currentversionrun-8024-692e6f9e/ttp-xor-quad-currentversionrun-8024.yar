rule TTP_XOR_QUAD_CurrentVersionRun_8024 {
  strings:
    $key_8024 = { d3 4b [2] f7 45 [2] dc 69 [2] f2 4b [2] e6 50 [2] e9 4a [2] f7 57 [2] f5 56 [2] ee 50 [2] f2 57 [2] ee 78 }

  condition:
    any of them
}