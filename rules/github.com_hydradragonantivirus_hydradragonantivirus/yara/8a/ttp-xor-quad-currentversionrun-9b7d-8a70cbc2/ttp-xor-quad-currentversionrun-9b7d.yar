rule TTP_XOR_QUAD_CurrentVersionRun_9b7d {
  strings:
    $key_9b7d = { c8 12 [2] ec 1c [2] c7 30 [2] e9 12 [2] fd 09 [2] f2 13 [2] ec 0e [2] ee 0f [2] f5 09 [2] e9 0e [2] f5 21 }

  condition:
    any of them
}