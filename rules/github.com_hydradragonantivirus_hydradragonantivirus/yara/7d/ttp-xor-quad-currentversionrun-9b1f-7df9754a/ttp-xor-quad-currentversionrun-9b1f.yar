rule TTP_XOR_QUAD_CurrentVersionRun_9b1f {
  strings:
    $key_9b1f = { c8 70 [2] ec 7e [2] c7 52 [2] e9 70 [2] fd 6b [2] f2 71 [2] ec 6c [2] ee 6d [2] f5 6b [2] e9 6c [2] f5 43 }

  condition:
    any of them
}