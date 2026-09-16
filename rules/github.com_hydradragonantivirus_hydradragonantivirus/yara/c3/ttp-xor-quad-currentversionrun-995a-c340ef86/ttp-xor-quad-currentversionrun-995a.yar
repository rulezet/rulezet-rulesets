rule TTP_XOR_QUAD_CurrentVersionRun_995a {
  strings:
    $key_995a = { ca 35 [2] ee 3b [2] c5 17 [2] eb 35 [2] ff 2e [2] f0 34 [2] ee 29 [2] ec 28 [2] f7 2e [2] eb 29 [2] f7 06 }

  condition:
    any of them
}