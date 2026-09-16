rule TTP_XOR_QUAD_CurrentVersionRun_9bf3 {
  strings:
    $key_9bf3 = { c8 9c [2] ec 92 [2] c7 be [2] e9 9c [2] fd 87 [2] f2 9d [2] ec 80 [2] ee 81 [2] f5 87 [2] e9 80 [2] f5 af }

  condition:
    any of them
}