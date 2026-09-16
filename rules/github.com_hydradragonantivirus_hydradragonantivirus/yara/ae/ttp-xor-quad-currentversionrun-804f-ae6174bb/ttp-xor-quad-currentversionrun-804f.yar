rule TTP_XOR_QUAD_CurrentVersionRun_804f {
  strings:
    $key_804f = { d3 20 [2] f7 2e [2] dc 02 [2] f2 20 [2] e6 3b [2] e9 21 [2] f7 3c [2] f5 3d [2] ee 3b [2] f2 3c [2] ee 13 }

  condition:
    any of them
}