rule TTP_XOR_QUAD_CurrentVersionRun_9bfa {
  strings:
    $key_9bfa = { c8 95 [2] ec 9b [2] c7 b7 [2] e9 95 [2] fd 8e [2] f2 94 [2] ec 89 [2] ee 88 [2] f5 8e [2] e9 89 [2] f5 a6 }

  condition:
    any of them
}