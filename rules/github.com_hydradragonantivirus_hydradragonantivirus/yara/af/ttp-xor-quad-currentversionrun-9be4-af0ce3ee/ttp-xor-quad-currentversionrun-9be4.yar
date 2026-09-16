rule TTP_XOR_QUAD_CurrentVersionRun_9be4 {
  strings:
    $key_9be4 = { c8 8b [2] ec 85 [2] c7 a9 [2] e9 8b [2] fd 90 [2] f2 8a [2] ec 97 [2] ee 96 [2] f5 90 [2] e9 97 [2] f5 b8 }

  condition:
    any of them
}