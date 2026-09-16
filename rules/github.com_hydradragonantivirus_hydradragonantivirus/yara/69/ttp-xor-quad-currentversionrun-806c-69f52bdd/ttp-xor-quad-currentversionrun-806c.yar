rule TTP_XOR_QUAD_CurrentVersionRun_806c {
  strings:
    $key_806c = { d3 03 [2] f7 0d [2] dc 21 [2] f2 03 [2] e6 18 [2] e9 02 [2] f7 1f [2] f5 1e [2] ee 18 [2] f2 1f [2] ee 30 }

  condition:
    any of them
}