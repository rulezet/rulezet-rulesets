rule TTP_XOR_QUAD_CurrentVersionRun_99d9 {
  strings:
    $key_99d9 = { ca b6 [2] ee b8 [2] c5 94 [2] eb b6 [2] ff ad [2] f0 b7 [2] ee aa [2] ec ab [2] f7 ad [2] eb aa [2] f7 85 }

  condition:
    any of them
}