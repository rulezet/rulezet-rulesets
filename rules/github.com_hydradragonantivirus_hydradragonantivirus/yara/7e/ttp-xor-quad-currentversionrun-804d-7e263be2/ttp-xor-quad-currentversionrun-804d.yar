rule TTP_XOR_QUAD_CurrentVersionRun_804d {
  strings:
    $key_804d = { d3 22 [2] f7 2c [2] dc 00 [2] f2 22 [2] e6 39 [2] e9 23 [2] f7 3e [2] f5 3f [2] ee 39 [2] f2 3e [2] ee 11 }

  condition:
    any of them
}