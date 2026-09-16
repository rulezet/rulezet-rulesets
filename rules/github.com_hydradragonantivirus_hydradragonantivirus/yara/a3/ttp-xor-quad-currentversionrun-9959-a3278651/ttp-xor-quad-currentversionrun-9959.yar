rule TTP_XOR_QUAD_CurrentVersionRun_9959 {
  strings:
    $key_9959 = { ca 36 [2] ee 38 [2] c5 14 [2] eb 36 [2] ff 2d [2] f0 37 [2] ee 2a [2] ec 2b [2] f7 2d [2] eb 2a [2] f7 05 }

  condition:
    any of them
}