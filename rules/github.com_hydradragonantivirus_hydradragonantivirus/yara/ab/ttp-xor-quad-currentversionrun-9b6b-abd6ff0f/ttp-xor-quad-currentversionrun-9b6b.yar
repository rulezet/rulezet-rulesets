rule TTP_XOR_QUAD_CurrentVersionRun_9b6b {
  strings:
    $key_9b6b = { c8 04 [2] ec 0a [2] c7 26 [2] e9 04 [2] fd 1f [2] f2 05 [2] ec 18 [2] ee 19 [2] f5 1f [2] e9 18 [2] f5 37 }

  condition:
    any of them
}