rule TTP_XOR_QUAD_CurrentVersionRun_871e {
  strings:
    $key_871e = { d4 71 [2] f0 7f [2] db 53 [2] f5 71 [2] e1 6a [2] ee 70 [2] f0 6d [2] f2 6c [2] e9 6a [2] f5 6d [2] e9 42 }

  condition:
    any of them
}