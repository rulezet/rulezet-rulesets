rule TTP_XOR_QUAD_CurrentVersionRun_9961 {
  strings:
    $key_9961 = { ca 0e [2] ee 00 [2] c5 2c [2] eb 0e [2] ff 15 [2] f0 0f [2] ee 12 [2] ec 13 [2] f7 15 [2] eb 12 [2] f7 3d }

  condition:
    any of them
}