rule TTP_XOR_QUAD_CurrentVersionRun_9b4a {
  strings:
    $key_9b4a = { c8 25 [2] ec 2b [2] c7 07 [2] e9 25 [2] fd 3e [2] f2 24 [2] ec 39 [2] ee 38 [2] f5 3e [2] e9 39 [2] f5 16 }

  condition:
    any of them
}