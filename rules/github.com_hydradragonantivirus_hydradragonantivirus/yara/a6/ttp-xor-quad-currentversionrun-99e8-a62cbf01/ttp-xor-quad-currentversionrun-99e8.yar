rule TTP_XOR_QUAD_CurrentVersionRun_99e8 {
  strings:
    $key_99e8 = { ca 87 [2] ee 89 [2] c5 a5 [2] eb 87 [2] ff 9c [2] f0 86 [2] ee 9b [2] ec 9a [2] f7 9c [2] eb 9b [2] f7 b4 }

  condition:
    any of them
}