rule TTP_XOR_QUAD_CurrentVersionRun_9b3a {
  strings:
    $key_9b3a = { c8 55 [2] ec 5b [2] c7 77 [2] e9 55 [2] fd 4e [2] f2 54 [2] ec 49 [2] ee 48 [2] f5 4e [2] e9 49 [2] f5 66 }

  condition:
    any of them
}