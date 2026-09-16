rule TTP_XOR_QUAD_CurrentVersionRun_9955 {
  strings:
    $key_9955 = { ca 3a [2] ee 34 [2] c5 18 [2] eb 3a [2] ff 21 [2] f0 3b [2] ee 26 [2] ec 27 [2] f7 21 [2] eb 26 [2] f7 09 }

  condition:
    any of them
}