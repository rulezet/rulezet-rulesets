rule TTP_XOR_QUAD_CurrentVersionRun_9979 {
  strings:
    $key_9979 = { ca 16 [2] ee 18 [2] c5 34 [2] eb 16 [2] ff 0d [2] f0 17 [2] ee 0a [2] ec 0b [2] f7 0d [2] eb 0a [2] f7 25 }

  condition:
    any of them
}