rule TTP_XOR_QUAD_CurrentVersionRun_99e5 {
  strings:
    $key_99e5 = { ca 8a [2] ee 84 [2] c5 a8 [2] eb 8a [2] ff 91 [2] f0 8b [2] ee 96 [2] ec 97 [2] f7 91 [2] eb 96 [2] f7 b9 }

  condition:
    any of them
}