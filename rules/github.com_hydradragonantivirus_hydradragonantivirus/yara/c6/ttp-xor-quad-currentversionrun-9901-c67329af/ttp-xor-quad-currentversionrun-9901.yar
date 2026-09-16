rule TTP_XOR_QUAD_CurrentVersionRun_9901 {
  strings:
    $key_9901 = { ca 6e [2] ee 60 [2] c5 4c [2] eb 6e [2] ff 75 [2] f0 6f [2] ee 72 [2] ec 73 [2] f7 75 [2] eb 72 [2] f7 5d }

  condition:
    any of them
}