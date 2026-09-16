rule TTP_XOR_QUAD_CurrentVersionRun_800d {
  strings:
    $key_800d = { d3 62 [2] f7 6c [2] dc 40 [2] f2 62 [2] e6 79 [2] e9 63 [2] f7 7e [2] f5 7f [2] ee 79 [2] f2 7e [2] ee 51 }

  condition:
    any of them
}