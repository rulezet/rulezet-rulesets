rule TTP_XOR_QUAD_CurrentVersionRun_9958 {
  strings:
    $key_9958 = { ca 37 [2] ee 39 [2] c5 15 [2] eb 37 [2] ff 2c [2] f0 36 [2] ee 2b [2] ec 2a [2] f7 2c [2] eb 2b [2] f7 04 }

  condition:
    any of them
}