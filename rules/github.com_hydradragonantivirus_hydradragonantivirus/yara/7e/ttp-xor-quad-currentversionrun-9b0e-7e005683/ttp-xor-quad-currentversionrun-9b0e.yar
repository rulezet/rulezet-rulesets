rule TTP_XOR_QUAD_CurrentVersionRun_9b0e {
  strings:
    $key_9b0e = { c8 61 [2] ec 6f [2] c7 43 [2] e9 61 [2] fd 7a [2] f2 60 [2] ec 7d [2] ee 7c [2] f5 7a [2] e9 7d [2] f5 52 }

  condition:
    any of them
}