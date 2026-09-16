rule TTP_XOR_QUAD_CurrentVersionRun_9b39 {
  strings:
    $key_9b39 = { c8 56 [2] ec 58 [2] c7 74 [2] e9 56 [2] fd 4d [2] f2 57 [2] ec 4a [2] ee 4b [2] f5 4d [2] e9 4a [2] f5 65 }

  condition:
    any of them
}