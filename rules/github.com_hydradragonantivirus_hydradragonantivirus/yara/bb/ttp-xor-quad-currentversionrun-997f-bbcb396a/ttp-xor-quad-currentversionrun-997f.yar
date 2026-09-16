rule TTP_XOR_QUAD_CurrentVersionRun_997f {
  strings:
    $key_997f = { ca 10 [2] ee 1e [2] c5 32 [2] eb 10 [2] ff 0b [2] f0 11 [2] ee 0c [2] ec 0d [2] f7 0b [2] eb 0c [2] f7 23 }

  condition:
    any of them
}