rule TTP_XOR_QUAD_CurrentVersionRun_990b {
  strings:
    $key_990b = { ca 64 [2] ee 6a [2] c5 46 [2] eb 64 [2] ff 7f [2] f0 65 [2] ee 78 [2] ec 79 [2] f7 7f [2] eb 78 [2] f7 57 }

  condition:
    any of them
}