rule TTP_XOR_QUAD_CurrentVersionRun_9b03 {
  strings:
    $key_9b03 = { c8 6c [2] ec 62 [2] c7 4e [2] e9 6c [2] fd 77 [2] f2 6d [2] ec 70 [2] ee 71 [2] f5 77 [2] e9 70 [2] f5 5f }

  condition:
    any of them
}