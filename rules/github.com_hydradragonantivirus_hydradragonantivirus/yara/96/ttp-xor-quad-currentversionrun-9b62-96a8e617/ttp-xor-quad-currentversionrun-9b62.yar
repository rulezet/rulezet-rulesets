rule TTP_XOR_QUAD_CurrentVersionRun_9b62 {
  strings:
    $key_9b62 = { c8 0d [2] ec 03 [2] c7 2f [2] e9 0d [2] fd 16 [2] f2 0c [2] ec 11 [2] ee 10 [2] f5 16 [2] e9 11 [2] f5 3e }

  condition:
    any of them
}