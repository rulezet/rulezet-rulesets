rule TTP_XOR_QUAD_CurrentVersionRun_9924 {
  strings:
    $key_9924 = { ca 4b [2] ee 45 [2] c5 69 [2] eb 4b [2] ff 50 [2] f0 4a [2] ee 57 [2] ec 56 [2] f7 50 [2] eb 57 [2] f7 78 }

  condition:
    any of them
}