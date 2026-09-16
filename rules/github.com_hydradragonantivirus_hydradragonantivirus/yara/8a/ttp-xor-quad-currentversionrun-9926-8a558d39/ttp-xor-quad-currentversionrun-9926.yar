rule TTP_XOR_QUAD_CurrentVersionRun_9926 {
  strings:
    $key_9926 = { ca 49 [2] ee 47 [2] c5 6b [2] eb 49 [2] ff 52 [2] f0 48 [2] ee 55 [2] ec 54 [2] f7 52 [2] eb 55 [2] f7 7a }

  condition:
    any of them
}