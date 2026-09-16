rule TTP_XOR_QUAD_CurrentVersionRun_99fb {
  strings:
    $key_99fb = { ca 94 [2] ee 9a [2] c5 b6 [2] eb 94 [2] ff 8f [2] f0 95 [2] ee 88 [2] ec 89 [2] f7 8f [2] eb 88 [2] f7 a7 }

  condition:
    any of them
}