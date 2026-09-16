rule TTP_XOR_QUAD_CurrentVersionRun_8010 {
  strings:
    $key_8010 = { d3 7f [2] f7 71 [2] dc 5d [2] f2 7f [2] e6 64 [2] e9 7e [2] f7 63 [2] f5 62 [2] ee 64 [2] f2 63 [2] ee 4c }

  condition:
    any of them
}