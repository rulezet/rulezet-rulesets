rule TTP_XOR_QUAD_CurrentVersionRun_9b02 {
  strings:
    $key_9b02 = { c8 6d [2] ec 63 [2] c7 4f [2] e9 6d [2] fd 76 [2] f2 6c [2] ec 71 [2] ee 70 [2] f5 76 [2] e9 71 [2] f5 5e }

  condition:
    any of them
}