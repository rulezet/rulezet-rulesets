rule TTP_XOR_QUAD_CurrentVersionRun_806e {
  strings:
    $key_806e = { d3 01 [2] f7 0f [2] dc 23 [2] f2 01 [2] e6 1a [2] e9 00 [2] f7 1d [2] f5 1c [2] ee 1a [2] f2 1d [2] ee 32 }

  condition:
    any of them
}