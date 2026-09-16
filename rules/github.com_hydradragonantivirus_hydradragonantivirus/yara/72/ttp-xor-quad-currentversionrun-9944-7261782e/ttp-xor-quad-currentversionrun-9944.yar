rule TTP_XOR_QUAD_CurrentVersionRun_9944 {
  strings:
    $key_9944 = { ca 2b [2] ee 25 [2] c5 09 [2] eb 2b [2] ff 30 [2] f0 2a [2] ee 37 [2] ec 36 [2] f7 30 [2] eb 37 [2] f7 18 }

  condition:
    any of them
}