rule TTP_XOR_QUAD_CurrentVersionRun_9b22 {
  strings:
    $key_9b22 = { c8 4d [2] ec 43 [2] c7 6f [2] e9 4d [2] fd 56 [2] f2 4c [2] ec 51 [2] ee 50 [2] f5 56 [2] e9 51 [2] f5 7e }

  condition:
    any of them
}