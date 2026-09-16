rule TTP_XOR_QUAD_CurrentVersionRun_994b {
  strings:
    $key_994b = { ca 24 [2] ee 2a [2] c5 06 [2] eb 24 [2] ff 3f [2] f0 25 [2] ee 38 [2] ec 39 [2] f7 3f [2] eb 38 [2] f7 17 }

  condition:
    any of them
}