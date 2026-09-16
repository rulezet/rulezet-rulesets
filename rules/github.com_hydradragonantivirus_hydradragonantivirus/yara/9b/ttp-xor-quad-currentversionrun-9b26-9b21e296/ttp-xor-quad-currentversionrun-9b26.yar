rule TTP_XOR_QUAD_CurrentVersionRun_9b26 {
  strings:
    $key_9b26 = { c8 49 [2] ec 47 [2] c7 6b [2] e9 49 [2] fd 52 [2] f2 48 [2] ec 55 [2] ee 54 [2] f5 52 [2] e9 55 [2] f5 7a }

  condition:
    any of them
}