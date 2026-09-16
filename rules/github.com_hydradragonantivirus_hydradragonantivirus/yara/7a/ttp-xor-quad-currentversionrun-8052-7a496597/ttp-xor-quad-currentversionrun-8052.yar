rule TTP_XOR_QUAD_CurrentVersionRun_8052 {
  strings:
    $key_8052 = { d3 3d [2] f7 33 [2] dc 1f [2] f2 3d [2] e6 26 [2] e9 3c [2] f7 21 [2] f5 20 [2] ee 26 [2] f2 21 [2] ee 0e }

  condition:
    any of them
}