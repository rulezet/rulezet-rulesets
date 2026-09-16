rule TTP_XOR_QUAD_CurrentVersionRun_9937 {
  strings:
    $key_9937 = { ca 58 [2] ee 56 [2] c5 7a [2] eb 58 [2] ff 43 [2] f0 59 [2] ee 44 [2] ec 45 [2] f7 43 [2] eb 44 [2] f7 6b }

  condition:
    any of them
}