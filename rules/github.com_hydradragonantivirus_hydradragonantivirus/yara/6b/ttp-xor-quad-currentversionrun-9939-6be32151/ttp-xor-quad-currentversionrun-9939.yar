rule TTP_XOR_QUAD_CurrentVersionRun_9939 {
  strings:
    $key_9939 = { ca 56 [2] ee 58 [2] c5 74 [2] eb 56 [2] ff 4d [2] f0 57 [2] ee 4a [2] ec 4b [2] f7 4d [2] eb 4a [2] f7 65 }

  condition:
    any of them
}