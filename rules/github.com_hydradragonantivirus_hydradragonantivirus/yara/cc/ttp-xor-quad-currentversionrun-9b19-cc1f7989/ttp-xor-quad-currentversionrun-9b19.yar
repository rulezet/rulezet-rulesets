rule TTP_XOR_QUAD_CurrentVersionRun_9b19 {
  strings:
    $key_9b19 = { c8 76 [2] ec 78 [2] c7 54 [2] e9 76 [2] fd 6d [2] f2 77 [2] ec 6a [2] ee 6b [2] f5 6d [2] e9 6a [2] f5 45 }

  condition:
    any of them
}