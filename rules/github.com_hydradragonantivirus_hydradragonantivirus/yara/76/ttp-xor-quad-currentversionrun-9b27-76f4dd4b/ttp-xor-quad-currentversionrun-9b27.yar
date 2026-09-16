rule TTP_XOR_QUAD_CurrentVersionRun_9b27 {
  strings:
    $key_9b27 = { c8 48 [2] ec 46 [2] c7 6a [2] e9 48 [2] fd 53 [2] f2 49 [2] ec 54 [2] ee 55 [2] f5 53 [2] e9 54 [2] f5 7b }

  condition:
    any of them
}