rule TTP_XOR_QUAD_CurrentVersionRun_9b4d {
  strings:
    $key_9b4d = { c8 22 [2] ec 2c [2] c7 00 [2] e9 22 [2] fd 39 [2] f2 23 [2] ec 3e [2] ee 3f [2] f5 39 [2] e9 3e [2] f5 11 }

  condition:
    any of them
}