rule TTP_XOR_QUAD_CurrentVersionRun_9b64 {
  strings:
    $key_9b64 = { c8 0b [2] ec 05 [2] c7 29 [2] e9 0b [2] fd 10 [2] f2 0a [2] ec 17 [2] ee 16 [2] f5 10 [2] e9 17 [2] f5 38 }

  condition:
    any of them
}