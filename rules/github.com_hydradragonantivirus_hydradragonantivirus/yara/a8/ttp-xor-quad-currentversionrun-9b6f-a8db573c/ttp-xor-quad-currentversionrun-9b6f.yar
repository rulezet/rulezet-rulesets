rule TTP_XOR_QUAD_CurrentVersionRun_9b6f {
  strings:
    $key_9b6f = { c8 00 [2] ec 0e [2] c7 22 [2] e9 00 [2] fd 1b [2] f2 01 [2] ec 1c [2] ee 1d [2] f5 1b [2] e9 1c [2] f5 33 }

  condition:
    any of them
}