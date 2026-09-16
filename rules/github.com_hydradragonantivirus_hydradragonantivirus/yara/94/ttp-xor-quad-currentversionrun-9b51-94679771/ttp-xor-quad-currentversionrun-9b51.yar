rule TTP_XOR_QUAD_CurrentVersionRun_9b51 {
  strings:
    $key_9b51 = { c8 3e [2] ec 30 [2] c7 1c [2] e9 3e [2] fd 25 [2] f2 3f [2] ec 22 [2] ee 23 [2] f5 25 [2] e9 22 [2] f5 0d }

  condition:
    any of them
}