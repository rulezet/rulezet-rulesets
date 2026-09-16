rule TTP_XOR_QUAD_CurrentVersionRun_9967 {
  strings:
    $key_9967 = { ca 08 [2] ee 06 [2] c5 2a [2] eb 08 [2] ff 13 [2] f0 09 [2] ee 14 [2] ec 15 [2] f7 13 [2] eb 14 [2] f7 3b }

  condition:
    any of them
}