rule TTP_XOR_QUAD_CurrentVersionRun_9b78 {
  strings:
    $key_9b78 = { c8 17 [2] ec 19 [2] c7 35 [2] e9 17 [2] fd 0c [2] f2 16 [2] ec 0b [2] ee 0a [2] f5 0c [2] e9 0b [2] f5 24 }

  condition:
    any of them
}