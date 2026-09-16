rule TTP_XOR_QUAD_CurrentVersionRun_800e {
  strings:
    $key_800e = { d3 61 [2] f7 6f [2] dc 43 [2] f2 61 [2] e6 7a [2] e9 60 [2] f7 7d [2] f5 7c [2] ee 7a [2] f2 7d [2] ee 52 }

  condition:
    any of them
}