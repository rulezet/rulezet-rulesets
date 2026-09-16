rule TTP_XOR_QUAD_CurrentVersionRun_9bed {
  strings:
    $key_9bed = { c8 82 [2] ec 8c [2] c7 a0 [2] e9 82 [2] fd 99 [2] f2 83 [2] ec 9e [2] ee 9f [2] f5 99 [2] e9 9e [2] f5 b1 }

  condition:
    any of them
}