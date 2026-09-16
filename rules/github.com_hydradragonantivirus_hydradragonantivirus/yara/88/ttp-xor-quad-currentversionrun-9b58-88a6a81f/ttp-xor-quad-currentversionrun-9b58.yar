rule TTP_XOR_QUAD_CurrentVersionRun_9b58 {
  strings:
    $key_9b58 = { c8 37 [2] ec 39 [2] c7 15 [2] e9 37 [2] fd 2c [2] f2 36 [2] ec 2b [2] ee 2a [2] f5 2c [2] e9 2b [2] f5 04 }

  condition:
    any of them
}