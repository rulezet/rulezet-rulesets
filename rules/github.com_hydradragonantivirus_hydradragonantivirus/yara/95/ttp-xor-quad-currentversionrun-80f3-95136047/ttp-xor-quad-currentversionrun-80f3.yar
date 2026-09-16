rule TTP_XOR_QUAD_CurrentVersionRun_80f3 {
  strings:
    $key_80f3 = { d3 9c [2] f7 92 [2] dc be [2] f2 9c [2] e6 87 [2] e9 9d [2] f7 80 [2] f5 81 [2] ee 87 [2] f2 80 [2] ee af }

  condition:
    any of them
}