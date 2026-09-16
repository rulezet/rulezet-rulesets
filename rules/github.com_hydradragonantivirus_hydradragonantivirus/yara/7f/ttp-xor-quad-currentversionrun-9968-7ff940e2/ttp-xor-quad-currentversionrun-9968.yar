rule TTP_XOR_QUAD_CurrentVersionRun_9968 {
  strings:
    $key_9968 = { ca 07 [2] ee 09 [2] c5 25 [2] eb 07 [2] ff 1c [2] f0 06 [2] ee 1b [2] ec 1a [2] f7 1c [2] eb 1b [2] f7 34 }

  condition:
    any of them
}