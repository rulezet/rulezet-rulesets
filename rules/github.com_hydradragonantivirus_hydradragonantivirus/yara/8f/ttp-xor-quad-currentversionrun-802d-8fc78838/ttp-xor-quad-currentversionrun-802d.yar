rule TTP_XOR_QUAD_CurrentVersionRun_802d {
  strings:
    $key_802d = { d3 42 [2] f7 4c [2] dc 60 [2] f2 42 [2] e6 59 [2] e9 43 [2] f7 5e [2] f5 5f [2] ee 59 [2] f2 5e [2] ee 71 }

  condition:
    any of them
}