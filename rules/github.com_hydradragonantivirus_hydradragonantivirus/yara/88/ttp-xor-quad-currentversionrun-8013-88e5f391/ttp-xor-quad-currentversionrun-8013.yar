rule TTP_XOR_QUAD_CurrentVersionRun_8013 {
  strings:
    $key_8013 = { d3 7c [2] f7 72 [2] dc 5e [2] f2 7c [2] e6 67 [2] e9 7d [2] f7 60 [2] f5 61 [2] ee 67 [2] f2 60 [2] ee 4f }

  condition:
    any of them
}