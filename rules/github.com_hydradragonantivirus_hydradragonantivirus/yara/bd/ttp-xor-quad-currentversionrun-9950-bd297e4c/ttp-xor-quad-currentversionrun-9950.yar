rule TTP_XOR_QUAD_CurrentVersionRun_9950 {
  strings:
    $key_9950 = { ca 3f [2] ee 31 [2] c5 1d [2] eb 3f [2] ff 24 [2] f0 3e [2] ee 23 [2] ec 22 [2] f7 24 [2] eb 23 [2] f7 0c }

  condition:
    any of them
}