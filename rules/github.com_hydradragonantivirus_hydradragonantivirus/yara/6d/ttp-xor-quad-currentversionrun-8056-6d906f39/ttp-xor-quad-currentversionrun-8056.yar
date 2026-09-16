rule TTP_XOR_QUAD_CurrentVersionRun_8056 {
  strings:
    $key_8056 = { d3 39 [2] f7 37 [2] dc 1b [2] f2 39 [2] e6 22 [2] e9 38 [2] f7 25 [2] f5 24 [2] ee 22 [2] f2 25 [2] ee 0a }

  condition:
    any of them
}