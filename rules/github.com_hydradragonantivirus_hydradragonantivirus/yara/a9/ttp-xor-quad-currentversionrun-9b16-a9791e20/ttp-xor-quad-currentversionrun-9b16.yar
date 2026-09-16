rule TTP_XOR_QUAD_CurrentVersionRun_9b16 {
  strings:
    $key_9b16 = { c8 79 [2] ec 77 [2] c7 5b [2] e9 79 [2] fd 62 [2] f2 78 [2] ec 65 [2] ee 64 [2] f5 62 [2] e9 65 [2] f5 4a }

  condition:
    any of them
}