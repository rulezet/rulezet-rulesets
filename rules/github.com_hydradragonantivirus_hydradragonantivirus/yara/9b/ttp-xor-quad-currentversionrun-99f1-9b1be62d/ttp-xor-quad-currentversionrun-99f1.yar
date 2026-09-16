rule TTP_XOR_QUAD_CurrentVersionRun_99f1 {
  strings:
    $key_99f1 = { ca 9e [2] ee 90 [2] c5 bc [2] eb 9e [2] ff 85 [2] f0 9f [2] ee 82 [2] ec 83 [2] f7 85 [2] eb 82 [2] f7 ad }

  condition:
    any of them
}