rule TTP_XOR_QUAD_CurrentVersionRun_9b36 {
  strings:
    $key_9b36 = { c8 59 [2] ec 57 [2] c7 7b [2] e9 59 [2] fd 42 [2] f2 58 [2] ec 45 [2] ee 44 [2] f5 42 [2] e9 45 [2] f5 6a }

  condition:
    any of them
}