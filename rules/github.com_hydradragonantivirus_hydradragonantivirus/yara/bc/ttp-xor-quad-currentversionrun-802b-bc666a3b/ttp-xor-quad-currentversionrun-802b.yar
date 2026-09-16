rule TTP_XOR_QUAD_CurrentVersionRun_802b {
  strings:
    $key_802b = { d3 44 [2] f7 4a [2] dc 66 [2] f2 44 [2] e6 5f [2] e9 45 [2] f7 58 [2] f5 59 [2] ee 5f [2] f2 58 [2] ee 77 }

  condition:
    any of them
}