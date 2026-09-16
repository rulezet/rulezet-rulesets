rule TTP_XOR_QUAD_CurrentVersionRun_9b05 {
  strings:
    $key_9b05 = { c8 6a [2] ec 64 [2] c7 48 [2] e9 6a [2] fd 71 [2] f2 6b [2] ec 76 [2] ee 77 [2] f5 71 [2] e9 76 [2] f5 59 }

  condition:
    any of them
}