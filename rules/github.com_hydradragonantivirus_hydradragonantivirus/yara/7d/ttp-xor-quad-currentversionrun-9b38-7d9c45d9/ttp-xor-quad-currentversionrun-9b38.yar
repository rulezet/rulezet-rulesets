rule TTP_XOR_QUAD_CurrentVersionRun_9b38 {
  strings:
    $key_9b38 = { c8 57 [2] ec 59 [2] c7 75 [2] e9 57 [2] fd 4c [2] f2 56 [2] ec 4b [2] ee 4a [2] f5 4c [2] e9 4b [2] f5 64 }

  condition:
    any of them
}