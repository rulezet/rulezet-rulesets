rule TTP_XOR_QUAD_CurrentVersionRun_9974 {
  strings:
    $key_9974 = { ca 1b [2] ee 15 [2] c5 39 [2] eb 1b [2] ff 00 [2] f0 1a [2] ee 07 [2] ec 06 [2] f7 00 [2] eb 07 [2] f7 28 }

  condition:
    any of them
}