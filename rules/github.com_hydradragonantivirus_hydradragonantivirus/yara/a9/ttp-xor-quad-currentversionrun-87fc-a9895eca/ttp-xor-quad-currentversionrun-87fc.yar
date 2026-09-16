rule TTP_XOR_QUAD_CurrentVersionRun_87fc {
  strings:
    $key_87fc = { d4 93 [2] f0 9d [2] db b1 [2] f5 93 [2] e1 88 [2] ee 92 [2] f0 8f [2] f2 8e [2] e9 88 [2] f5 8f [2] e9 a0 }

  condition:
    any of them
}