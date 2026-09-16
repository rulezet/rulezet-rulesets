rule TTP_XOR_QUAD_CurrentVersionRun_9b2d {
  strings:
    $key_9b2d = { c8 42 [2] ec 4c [2] c7 60 [2] e9 42 [2] fd 59 [2] f2 43 [2] ec 5e [2] ee 5f [2] f5 59 [2] e9 5e [2] f5 71 }

  condition:
    any of them
}