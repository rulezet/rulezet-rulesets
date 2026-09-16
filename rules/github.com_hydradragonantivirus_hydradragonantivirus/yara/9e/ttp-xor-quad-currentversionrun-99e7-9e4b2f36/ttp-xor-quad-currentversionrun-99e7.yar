rule TTP_XOR_QUAD_CurrentVersionRun_99e7 {
  strings:
    $key_99e7 = { ca 88 [2] ee 86 [2] c5 aa [2] eb 88 [2] ff 93 [2] f0 89 [2] ee 94 [2] ec 95 [2] f7 93 [2] eb 94 [2] f7 bb }

  condition:
    any of them
}