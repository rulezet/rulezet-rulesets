rule TTP_XOR_QUAD_CurrentVersionRun_9b06 {
  strings:
    $key_9b06 = { c8 69 [2] ec 67 [2] c7 4b [2] e9 69 [2] fd 72 [2] f2 68 [2] ec 75 [2] ee 74 [2] f5 72 [2] e9 75 [2] f5 5a }

  condition:
    any of them
}