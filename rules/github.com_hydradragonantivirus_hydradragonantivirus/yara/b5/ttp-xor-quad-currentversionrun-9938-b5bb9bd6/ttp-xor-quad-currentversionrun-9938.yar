rule TTP_XOR_QUAD_CurrentVersionRun_9938 {
  strings:
    $key_9938 = { ca 57 [2] ee 59 [2] c5 75 [2] eb 57 [2] ff 4c [2] f0 56 [2] ee 4b [2] ec 4a [2] f7 4c [2] eb 4b [2] f7 64 }

  condition:
    any of them
}