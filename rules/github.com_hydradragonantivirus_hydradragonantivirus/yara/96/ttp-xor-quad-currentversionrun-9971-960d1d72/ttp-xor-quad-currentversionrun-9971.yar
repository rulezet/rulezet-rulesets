rule TTP_XOR_QUAD_CurrentVersionRun_9971 {
  strings:
    $key_9971 = { ca 1e [2] ee 10 [2] c5 3c [2] eb 1e [2] ff 05 [2] f0 1f [2] ee 02 [2] ec 03 [2] f7 05 [2] eb 02 [2] f7 2d }

  condition:
    any of them
}