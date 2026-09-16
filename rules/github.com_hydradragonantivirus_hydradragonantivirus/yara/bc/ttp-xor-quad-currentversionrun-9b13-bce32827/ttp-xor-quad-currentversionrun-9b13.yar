rule TTP_XOR_QUAD_CurrentVersionRun_9b13 {
  strings:
    $key_9b13 = { c8 7c [2] ec 72 [2] c7 5e [2] e9 7c [2] fd 67 [2] f2 7d [2] ec 60 [2] ee 61 [2] f5 67 [2] e9 60 [2] f5 4f }

  condition:
    any of them
}