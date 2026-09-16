rule TTP_XOR_QUAD_CurrentVersionRun_9b14 {
  strings:
    $key_9b14 = { c8 7b [2] ec 75 [2] c7 59 [2] e9 7b [2] fd 60 [2] f2 7a [2] ec 67 [2] ee 66 [2] f5 60 [2] e9 67 [2] f5 48 }

  condition:
    any of them
}