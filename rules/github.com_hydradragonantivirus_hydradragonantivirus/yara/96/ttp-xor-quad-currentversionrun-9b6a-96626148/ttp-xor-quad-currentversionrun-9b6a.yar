rule TTP_XOR_QUAD_CurrentVersionRun_9b6a {
  strings:
    $key_9b6a = { c8 05 [2] ec 0b [2] c7 27 [2] e9 05 [2] fd 1e [2] f2 04 [2] ec 19 [2] ee 18 [2] f5 1e [2] e9 19 [2] f5 36 }

  condition:
    any of them
}