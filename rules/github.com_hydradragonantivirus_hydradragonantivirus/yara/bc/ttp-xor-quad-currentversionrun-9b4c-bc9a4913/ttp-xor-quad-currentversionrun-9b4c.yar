rule TTP_XOR_QUAD_CurrentVersionRun_9b4c {
  strings:
    $key_9b4c = { c8 23 [2] ec 2d [2] c7 01 [2] e9 23 [2] fd 38 [2] f2 22 [2] ec 3f [2] ee 3e [2] f5 38 [2] e9 3f [2] f5 10 }

  condition:
    any of them
}