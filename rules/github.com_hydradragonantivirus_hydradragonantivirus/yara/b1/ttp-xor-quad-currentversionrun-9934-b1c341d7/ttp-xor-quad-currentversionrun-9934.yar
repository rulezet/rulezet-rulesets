rule TTP_XOR_QUAD_CurrentVersionRun_9934 {
  strings:
    $key_9934 = { ca 5b [2] ee 55 [2] c5 79 [2] eb 5b [2] ff 40 [2] f0 5a [2] ee 47 [2] ec 46 [2] f7 40 [2] eb 47 [2] f7 68 }

  condition:
    any of them
}