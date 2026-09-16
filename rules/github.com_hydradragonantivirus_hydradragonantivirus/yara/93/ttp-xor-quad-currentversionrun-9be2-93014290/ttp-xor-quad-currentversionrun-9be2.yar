rule TTP_XOR_QUAD_CurrentVersionRun_9be2 {
  strings:
    $key_9be2 = { c8 8d [2] ec 83 [2] c7 af [2] e9 8d [2] fd 96 [2] f2 8c [2] ec 91 [2] ee 90 [2] f5 96 [2] e9 91 [2] f5 be }

  condition:
    any of them
}