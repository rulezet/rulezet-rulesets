rule TTP_XOR_QUAD_CurrentVersionRun_9977 {
  strings:
    $key_9977 = { ca 18 [2] ee 16 [2] c5 3a [2] eb 18 [2] ff 03 [2] f0 19 [2] ee 04 [2] ec 05 [2] f7 03 [2] eb 04 [2] f7 2b }

  condition:
    any of them
}