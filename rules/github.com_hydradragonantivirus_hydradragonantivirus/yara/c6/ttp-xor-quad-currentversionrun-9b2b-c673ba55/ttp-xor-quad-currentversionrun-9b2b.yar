rule TTP_XOR_QUAD_CurrentVersionRun_9b2b {
  strings:
    $key_9b2b = { c8 44 [2] ec 4a [2] c7 66 [2] e9 44 [2] fd 5f [2] f2 45 [2] ec 58 [2] ee 59 [2] f5 5f [2] e9 58 [2] f5 77 }

  condition:
    any of them
}