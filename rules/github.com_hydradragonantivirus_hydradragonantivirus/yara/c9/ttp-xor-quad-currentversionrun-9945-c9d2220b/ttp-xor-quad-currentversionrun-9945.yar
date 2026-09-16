rule TTP_XOR_QUAD_CurrentVersionRun_9945 {
  strings:
    $key_9945 = { ca 2a [2] ee 24 [2] c5 08 [2] eb 2a [2] ff 31 [2] f0 2b [2] ee 36 [2] ec 37 [2] f7 31 [2] eb 36 [2] f7 19 }

  condition:
    any of them
}