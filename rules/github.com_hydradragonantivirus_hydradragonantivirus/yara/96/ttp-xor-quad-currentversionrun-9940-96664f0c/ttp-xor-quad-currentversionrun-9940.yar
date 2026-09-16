rule TTP_XOR_QUAD_CurrentVersionRun_9940 {
  strings:
    $key_9940 = { ca 2f [2] ee 21 [2] c5 0d [2] eb 2f [2] ff 34 [2] f0 2e [2] ee 33 [2] ec 32 [2] f7 34 [2] eb 33 [2] f7 1c }

  condition:
    any of them
}