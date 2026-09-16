rule TTP_XOR_QUAD_CurrentVersionRun_9b1a {
  strings:
    $key_9b1a = { c8 75 [2] ec 7b [2] c7 57 [2] e9 75 [2] fd 6e [2] f2 74 [2] ec 69 [2] ee 68 [2] f5 6e [2] e9 69 [2] f5 46 }

  condition:
    any of them
}