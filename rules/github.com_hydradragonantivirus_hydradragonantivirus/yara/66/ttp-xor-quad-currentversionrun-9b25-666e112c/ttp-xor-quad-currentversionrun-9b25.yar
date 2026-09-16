rule TTP_XOR_QUAD_CurrentVersionRun_9b25 {
  strings:
    $key_9b25 = { c8 4a [2] ec 44 [2] c7 68 [2] e9 4a [2] fd 51 [2] f2 4b [2] ec 56 [2] ee 57 [2] f5 51 [2] e9 56 [2] f5 79 }

  condition:
    any of them
}