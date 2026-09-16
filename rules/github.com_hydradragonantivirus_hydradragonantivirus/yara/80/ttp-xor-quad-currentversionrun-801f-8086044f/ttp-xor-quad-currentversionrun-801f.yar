rule TTP_XOR_QUAD_CurrentVersionRun_801f {
  strings:
    $key_801f = { d3 70 [2] f7 7e [2] dc 52 [2] f2 70 [2] e6 6b [2] e9 71 [2] f7 6c [2] f5 6d [2] ee 6b [2] f2 6c [2] ee 43 }

  condition:
    any of them
}