rule TTP_XOR_QUAD_CurrentVersionRun_99ff {
  strings:
    $key_99ff = { ca 90 [2] ee 9e [2] c5 b2 [2] eb 90 [2] ff 8b [2] f0 91 [2] ee 8c [2] ec 8d [2] f7 8b [2] eb 8c [2] f7 a3 }

  condition:
    any of them
}