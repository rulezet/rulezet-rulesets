rule TTP_XOR_QUAD_CurrentVersionRun_9932 {
  strings:
    $key_9932 = { ca 5d [2] ee 53 [2] c5 7f [2] eb 5d [2] ff 46 [2] f0 5c [2] ee 41 [2] ec 40 [2] f7 46 [2] eb 41 [2] f7 6e }

  condition:
    any of them
}