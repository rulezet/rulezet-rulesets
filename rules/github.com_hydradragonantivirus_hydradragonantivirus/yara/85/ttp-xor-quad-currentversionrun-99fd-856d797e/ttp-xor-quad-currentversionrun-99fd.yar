rule TTP_XOR_QUAD_CurrentVersionRun_99fd {
  strings:
    $key_99fd = { ca 92 [2] ee 9c [2] c5 b0 [2] eb 92 [2] ff 89 [2] f0 93 [2] ee 8e [2] ec 8f [2] f7 89 [2] eb 8e [2] f7 a1 }

  condition:
    any of them
}