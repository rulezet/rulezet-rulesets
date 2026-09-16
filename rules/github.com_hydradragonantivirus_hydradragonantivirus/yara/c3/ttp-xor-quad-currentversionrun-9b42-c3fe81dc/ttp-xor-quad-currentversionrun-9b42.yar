rule TTP_XOR_QUAD_CurrentVersionRun_9b42 {
  strings:
    $key_9b42 = { c8 2d [2] ec 23 [2] c7 0f [2] e9 2d [2] fd 36 [2] f2 2c [2] ec 31 [2] ee 30 [2] f5 36 [2] e9 31 [2] f5 1e }

  condition:
    any of them
}