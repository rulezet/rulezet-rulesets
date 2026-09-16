rule TTP_XOR_QUAD_CurrentVersionRun_9b6d {
  strings:
    $key_9b6d = { c8 02 [2] ec 0c [2] c7 20 [2] e9 02 [2] fd 19 [2] f2 03 [2] ec 1e [2] ee 1f [2] f5 19 [2] e9 1e [2] f5 31 }

  condition:
    any of them
}