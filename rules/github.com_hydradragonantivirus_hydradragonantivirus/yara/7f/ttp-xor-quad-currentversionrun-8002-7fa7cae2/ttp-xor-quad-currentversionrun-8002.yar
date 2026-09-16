rule TTP_XOR_QUAD_CurrentVersionRun_8002 {
  strings:
    $key_8002 = { d3 6d [2] f7 63 [2] dc 4f [2] f2 6d [2] e6 76 [2] e9 6c [2] f7 71 [2] f5 70 [2] ee 76 [2] f2 71 [2] ee 5e }

  condition:
    any of them
}