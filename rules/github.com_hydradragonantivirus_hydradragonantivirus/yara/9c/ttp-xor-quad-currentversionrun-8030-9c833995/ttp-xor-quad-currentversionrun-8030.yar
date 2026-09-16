rule TTP_XOR_QUAD_CurrentVersionRun_8030 {
  strings:
    $key_8030 = { d3 5f [2] f7 51 [2] dc 7d [2] f2 5f [2] e6 44 [2] e9 5e [2] f7 43 [2] f5 42 [2] ee 44 [2] f2 43 [2] ee 6c }

  condition:
    any of them
}