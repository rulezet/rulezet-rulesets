rule TTP_XOR_QUAD_CurrentVersionRun_9b5a {
  strings:
    $key_9b5a = { c8 35 [2] ec 3b [2] c7 17 [2] e9 35 [2] fd 2e [2] f2 34 [2] ec 29 [2] ee 28 [2] f5 2e [2] e9 29 [2] f5 06 }

  condition:
    any of them
}