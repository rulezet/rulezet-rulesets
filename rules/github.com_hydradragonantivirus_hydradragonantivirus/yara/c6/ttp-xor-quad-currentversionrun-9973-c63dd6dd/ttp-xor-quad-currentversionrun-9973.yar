rule TTP_XOR_QUAD_CurrentVersionRun_9973 {
  strings:
    $key_9973 = { ca 1c [2] ee 12 [2] c5 3e [2] eb 1c [2] ff 07 [2] f0 1d [2] ee 00 [2] ec 01 [2] f7 07 [2] eb 00 [2] f7 2f }

  condition:
    any of them
}