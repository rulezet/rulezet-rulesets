rule TTP_XOR_QUAD_CurrentVersionRun_9907 {
  strings:
    $key_9907 = { ca 68 [2] ee 66 [2] c5 4a [2] eb 68 [2] ff 73 [2] f0 69 [2] ee 74 [2] ec 75 [2] f7 73 [2] eb 74 [2] f7 5b }

  condition:
    any of them
}