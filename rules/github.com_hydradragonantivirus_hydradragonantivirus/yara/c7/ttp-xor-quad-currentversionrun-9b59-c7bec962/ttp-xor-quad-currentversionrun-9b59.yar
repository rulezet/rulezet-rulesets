rule TTP_XOR_QUAD_CurrentVersionRun_9b59 {
  strings:
    $key_9b59 = { c8 36 [2] ec 38 [2] c7 14 [2] e9 36 [2] fd 2d [2] f2 37 [2] ec 2a [2] ee 2b [2] f5 2d [2] e9 2a [2] f5 05 }

  condition:
    any of them
}