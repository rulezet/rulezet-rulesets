rule TTP_XOR_QUAD_CurrentVersionRun_9b75 {
  strings:
    $key_9b75 = { c8 1a [2] ec 14 [2] c7 38 [2] e9 1a [2] fd 01 [2] f2 1b [2] ec 06 [2] ee 07 [2] f5 01 [2] e9 06 [2] f5 29 }

  condition:
    any of them
}