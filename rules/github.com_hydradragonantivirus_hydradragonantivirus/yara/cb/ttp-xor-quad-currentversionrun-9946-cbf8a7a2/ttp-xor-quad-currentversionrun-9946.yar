rule TTP_XOR_QUAD_CurrentVersionRun_9946 {
  strings:
    $key_9946 = { ca 29 [2] ee 27 [2] c5 0b [2] eb 29 [2] ff 32 [2] f0 28 [2] ee 35 [2] ec 34 [2] f7 32 [2] eb 35 [2] f7 1a }

  condition:
    any of them
}