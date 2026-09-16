rule TTP_XOR_QUAD_CurrentVersionRun_9b43 {
  strings:
    $key_9b43 = { c8 2c [2] ec 22 [2] c7 0e [2] e9 2c [2] fd 37 [2] f2 2d [2] ec 30 [2] ee 31 [2] f5 37 [2] e9 30 [2] f5 1f }

  condition:
    any of them
}