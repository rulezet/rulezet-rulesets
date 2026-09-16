rule TTP_XOR_QUAD_CurrentVersionRun_99e6 {
  strings:
    $key_99e6 = { ca 89 [2] ee 87 [2] c5 ab [2] eb 89 [2] ff 92 [2] f0 88 [2] ee 95 [2] ec 94 [2] f7 92 [2] eb 95 [2] f7 ba }

  condition:
    any of them
}