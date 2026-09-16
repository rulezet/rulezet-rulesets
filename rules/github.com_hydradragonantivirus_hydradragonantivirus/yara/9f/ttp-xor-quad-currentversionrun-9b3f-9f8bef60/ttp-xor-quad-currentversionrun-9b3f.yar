rule TTP_XOR_QUAD_CurrentVersionRun_9b3f {
  strings:
    $key_9b3f = { c8 50 [2] ec 5e [2] c7 72 [2] e9 50 [2] fd 4b [2] f2 51 [2] ec 4c [2] ee 4d [2] f5 4b [2] e9 4c [2] f5 63 }

  condition:
    any of them
}