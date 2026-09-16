rule TTP_XOR_QUAD_CurrentVersionRun_9bff {
  strings:
    $key_9bff = { c8 90 [2] ec 9e [2] c7 b2 [2] e9 90 [2] fd 8b [2] f2 91 [2] ec 8c [2] ee 8d [2] f5 8b [2] e9 8c [2] f5 a3 }

  condition:
    any of them
}