rule TTP_XOR_QUAD_CurrentVersionRun_9b3e {
  strings:
    $key_9b3e = { c8 51 [2] ec 5f [2] c7 73 [2] e9 51 [2] fd 4a [2] f2 50 [2] ec 4d [2] ee 4c [2] f5 4a [2] e9 4d [2] f5 62 }

  condition:
    any of them
}