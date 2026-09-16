rule TTP_XOR_QUAD_CurrentVersionRun_992a {
  strings:
    $key_992a = { ca 45 [2] ee 4b [2] c5 67 [2] eb 45 [2] ff 5e [2] f0 44 [2] ee 59 [2] ec 58 [2] f7 5e [2] eb 59 [2] f7 76 }

  condition:
    any of them
}