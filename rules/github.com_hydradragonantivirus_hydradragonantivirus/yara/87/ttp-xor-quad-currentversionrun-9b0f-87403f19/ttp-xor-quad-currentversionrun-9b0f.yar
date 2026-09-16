rule TTP_XOR_QUAD_CurrentVersionRun_9b0f {
  strings:
    $key_9b0f = { c8 60 [2] ec 6e [2] c7 42 [2] e9 60 [2] fd 7b [2] f2 61 [2] ec 7c [2] ee 7d [2] f5 7b [2] e9 7c [2] f5 53 }

  condition:
    any of them
}