rule TTP_XOR_QUAD_CurrentVersionRun_9911 {
  strings:
    $key_9911 = { ca 7e [2] ee 70 [2] c5 5c [2] eb 7e [2] ff 65 [2] f0 7f [2] ee 62 [2] ec 63 [2] f7 65 [2] eb 62 [2] f7 4d }

  condition:
    any of them
}