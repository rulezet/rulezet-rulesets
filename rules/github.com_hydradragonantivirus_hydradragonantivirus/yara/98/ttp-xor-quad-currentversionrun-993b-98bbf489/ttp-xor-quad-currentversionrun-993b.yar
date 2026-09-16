rule TTP_XOR_QUAD_CurrentVersionRun_993b {
  strings:
    $key_993b = { ca 54 [2] ee 5a [2] c5 76 [2] eb 54 [2] ff 4f [2] f0 55 [2] ee 48 [2] ec 49 [2] f7 4f [2] eb 48 [2] f7 67 }

  condition:
    any of them
}