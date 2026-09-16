rule TTP_XOR_QUAD_CurrentVersionRun_9b0a {
  strings:
    $key_9b0a = { c8 65 [2] ec 6b [2] c7 47 [2] e9 65 [2] fd 7e [2] f2 64 [2] ec 79 [2] ee 78 [2] f5 7e [2] e9 79 [2] f5 56 }

  condition:
    any of them
}