rule TTP_XOR_QUAD_CurrentVersionRun_9b5e {
  strings:
    $key_9b5e = { c8 31 [2] ec 3f [2] c7 13 [2] e9 31 [2] fd 2a [2] f2 30 [2] ec 2d [2] ee 2c [2] f5 2a [2] e9 2d [2] f5 02 }

  condition:
    any of them
}