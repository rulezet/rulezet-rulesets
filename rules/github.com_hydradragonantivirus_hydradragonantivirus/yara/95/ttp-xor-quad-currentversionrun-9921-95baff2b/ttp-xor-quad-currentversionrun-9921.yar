rule TTP_XOR_QUAD_CurrentVersionRun_9921 {
  strings:
    $key_9921 = { ca 4e [2] ee 40 [2] c5 6c [2] eb 4e [2] ff 55 [2] f0 4f [2] ee 52 [2] ec 53 [2] f7 55 [2] eb 52 [2] f7 7d }

  condition:
    any of them
}