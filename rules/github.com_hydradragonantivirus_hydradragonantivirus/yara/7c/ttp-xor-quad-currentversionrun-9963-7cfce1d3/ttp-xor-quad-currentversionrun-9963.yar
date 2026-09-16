rule TTP_XOR_QUAD_CurrentVersionRun_9963 {
  strings:
    $key_9963 = { ca 0c [2] ee 02 [2] c5 2e [2] eb 0c [2] ff 17 [2] f0 0d [2] ee 10 [2] ec 11 [2] f7 17 [2] eb 10 [2] f7 3f }

  condition:
    any of them
}