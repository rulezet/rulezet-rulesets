rule TTP_XOR_QUAD_CurrentVersionRun_87ff {
  strings:
    $key_87ff = { d4 90 [2] f0 9e [2] db b2 [2] f5 90 [2] e1 8b [2] ee 91 [2] f0 8c [2] f2 8d [2] e9 8b [2] f5 8c [2] e9 a3 }

  condition:
    any of them
}