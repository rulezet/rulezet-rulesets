rule TTP_XOR_QUAD_CurrentVersionRun_9903 {
  strings:
    $key_9903 = { ca 6c [2] ee 62 [2] c5 4e [2] eb 6c [2] ff 77 [2] f0 6d [2] ee 70 [2] ec 71 [2] f7 77 [2] eb 70 [2] f7 5f }

  condition:
    any of them
}