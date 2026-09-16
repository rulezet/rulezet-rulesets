rule TTP_XOR_QUAD_CurrentVersionRun_9b2e {
  strings:
    $key_9b2e = { c8 41 [2] ec 4f [2] c7 63 [2] e9 41 [2] fd 5a [2] f2 40 [2] ec 5d [2] ee 5c [2] f5 5a [2] e9 5d [2] f5 72 }

  condition:
    any of them
}