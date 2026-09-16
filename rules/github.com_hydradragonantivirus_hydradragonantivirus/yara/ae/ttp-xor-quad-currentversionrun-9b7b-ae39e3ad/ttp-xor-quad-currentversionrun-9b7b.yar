rule TTP_XOR_QUAD_CurrentVersionRun_9b7b {
  strings:
    $key_9b7b = { c8 14 [2] ec 1a [2] c7 36 [2] e9 14 [2] fd 0f [2] f2 15 [2] ec 08 [2] ee 09 [2] f5 0f [2] e9 08 [2] f5 27 }

  condition:
    any of them
}