rule TTP_XOR_QUAD_CurrentVersionRun_99f3 {
  strings:
    $key_99f3 = { ca 9c [2] ee 92 [2] c5 be [2] eb 9c [2] ff 87 [2] f0 9d [2] ee 80 [2] ec 81 [2] f7 87 [2] eb 80 [2] f7 af }

  condition:
    any of them
}