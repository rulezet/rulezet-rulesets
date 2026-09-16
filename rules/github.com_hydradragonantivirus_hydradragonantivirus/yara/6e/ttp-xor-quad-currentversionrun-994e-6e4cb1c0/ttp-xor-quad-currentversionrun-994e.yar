rule TTP_XOR_QUAD_CurrentVersionRun_994e {
  strings:
    $key_994e = { ca 21 [2] ee 2f [2] c5 03 [2] eb 21 [2] ff 3a [2] f0 20 [2] ee 3d [2] ec 3c [2] f7 3a [2] eb 3d [2] f7 12 }

  condition:
    any of them
}