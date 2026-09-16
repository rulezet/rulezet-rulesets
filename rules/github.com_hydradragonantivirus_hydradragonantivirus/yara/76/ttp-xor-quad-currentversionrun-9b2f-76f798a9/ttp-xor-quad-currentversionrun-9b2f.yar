rule TTP_XOR_QUAD_CurrentVersionRun_9b2f {
  strings:
    $key_9b2f = { c8 40 [2] ec 4e [2] c7 62 [2] e9 40 [2] fd 5b [2] f2 41 [2] ec 5c [2] ee 5d [2] f5 5b [2] e9 5c [2] f5 73 }

  condition:
    any of them
}