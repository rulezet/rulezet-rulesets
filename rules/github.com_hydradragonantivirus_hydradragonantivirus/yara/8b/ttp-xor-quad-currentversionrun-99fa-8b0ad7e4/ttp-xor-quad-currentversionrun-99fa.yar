rule TTP_XOR_QUAD_CurrentVersionRun_99fa {
  strings:
    $key_99fa = { ca 95 [2] ee 9b [2] c5 b7 [2] eb 95 [2] ff 8e [2] f0 94 [2] ee 89 [2] ec 88 [2] f7 8e [2] eb 89 [2] f7 a6 }

  condition:
    any of them
}