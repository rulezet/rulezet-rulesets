rule TTP_XOR_QUAD_CurrentVersionRun_99ef {
  strings:
    $key_99ef = { ca 80 [2] ee 8e [2] c5 a2 [2] eb 80 [2] ff 9b [2] f0 81 [2] ee 9c [2] ec 9d [2] f7 9b [2] eb 9c [2] f7 b3 }

  condition:
    any of them
}