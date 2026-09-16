rule TTP_XOR_QUAD_CurrentVersionRun_9962 {
  strings:
    $key_9962 = { ca 0d [2] ee 03 [2] c5 2f [2] eb 0d [2] ff 16 [2] f0 0c [2] ee 11 [2] ec 10 [2] f7 16 [2] eb 11 [2] f7 3e }

  condition:
    any of them
}