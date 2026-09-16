rule TTP_XOR_QUAD_CurrentVersionRun_87fb {
  strings:
    $key_87fb = { d4 94 [2] f0 9a [2] db b6 [2] f5 94 [2] e1 8f [2] ee 95 [2] f0 88 [2] f2 89 [2] e9 8f [2] f5 88 [2] e9 a7 }

  condition:
    any of them
}