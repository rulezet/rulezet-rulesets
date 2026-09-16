rule TTP_XOR_QUAD_CurrentVersionRun_9b66 {
  strings:
    $key_9b66 = { c8 09 [2] ec 07 [2] c7 2b [2] e9 09 [2] fd 12 [2] f2 08 [2] ec 15 [2] ee 14 [2] f5 12 [2] e9 15 [2] f5 3a }

  condition:
    any of them
}