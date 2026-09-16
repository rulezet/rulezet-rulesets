rule TTP_XOR_QUAD_CurrentVersionRun_8005 {
  strings:
    $key_8005 = { d3 6a [2] f7 64 [2] dc 48 [2] f2 6a [2] e6 71 [2] e9 6b [2] f7 76 [2] f5 77 [2] ee 71 [2] f2 76 [2] ee 59 }

  condition:
    any of them
}