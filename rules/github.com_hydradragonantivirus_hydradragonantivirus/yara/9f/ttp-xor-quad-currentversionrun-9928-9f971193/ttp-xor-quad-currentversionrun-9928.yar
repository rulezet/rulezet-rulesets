rule TTP_XOR_QUAD_CurrentVersionRun_9928 {
  strings:
    $key_9928 = { ca 47 [2] ee 49 [2] c5 65 [2] eb 47 [2] ff 5c [2] f0 46 [2] ee 5b [2] ec 5a [2] f7 5c [2] eb 5b [2] f7 74 }

  condition:
    any of them
}