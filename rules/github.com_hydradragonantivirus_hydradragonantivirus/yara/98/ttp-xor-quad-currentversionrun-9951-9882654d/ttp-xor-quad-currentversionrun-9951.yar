rule TTP_XOR_QUAD_CurrentVersionRun_9951 {
  strings:
    $key_9951 = { ca 3e [2] ee 30 [2] c5 1c [2] eb 3e [2] ff 25 [2] f0 3f [2] ee 22 [2] ec 23 [2] f7 25 [2] eb 22 [2] f7 0d }

  condition:
    any of them
}