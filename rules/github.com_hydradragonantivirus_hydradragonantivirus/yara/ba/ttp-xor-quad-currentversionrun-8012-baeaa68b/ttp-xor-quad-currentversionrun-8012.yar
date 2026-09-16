rule TTP_XOR_QUAD_CurrentVersionRun_8012 {
  strings:
    $key_8012 = { d3 7d [2] f7 73 [2] dc 5f [2] f2 7d [2] e6 66 [2] e9 7c [2] f7 61 [2] f5 60 [2] ee 66 [2] f2 61 [2] ee 4e }

  condition:
    any of them
}