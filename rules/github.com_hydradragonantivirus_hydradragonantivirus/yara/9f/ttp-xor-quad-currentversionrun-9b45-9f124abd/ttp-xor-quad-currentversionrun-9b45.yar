rule TTP_XOR_QUAD_CurrentVersionRun_9b45 {
  strings:
    $key_9b45 = { c8 2a [2] ec 24 [2] c7 08 [2] e9 2a [2] fd 31 [2] f2 2b [2] ec 36 [2] ee 37 [2] f5 31 [2] e9 36 [2] f5 19 }

  condition:
    any of them
}