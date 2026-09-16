rule TTP_XOR_QUAD_CurrentVersionRun_9b5d {
  strings:
    $key_9b5d = { c8 32 [2] ec 3c [2] c7 10 [2] e9 32 [2] fd 29 [2] f2 33 [2] ec 2e [2] ee 2f [2] f5 29 [2] e9 2e [2] f5 01 }

  condition:
    any of them
}