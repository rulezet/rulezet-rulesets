rule TTP_XOR_QUAD_CurrentVersionRun_9b5f {
  strings:
    $key_9b5f = { c8 30 [2] ec 3e [2] c7 12 [2] e9 30 [2] fd 2b [2] f2 31 [2] ec 2c [2] ee 2d [2] f5 2b [2] e9 2c [2] f5 03 }

  condition:
    any of them
}