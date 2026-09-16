rule TTP_XOR_QUAD_CurrentVersionRun_9912 {
  strings:
    $key_9912 = { ca 7d [2] ee 73 [2] c5 5f [2] eb 7d [2] ff 66 [2] f0 7c [2] ee 61 [2] ec 60 [2] f7 66 [2] eb 61 [2] f7 4e }

  condition:
    any of them
}