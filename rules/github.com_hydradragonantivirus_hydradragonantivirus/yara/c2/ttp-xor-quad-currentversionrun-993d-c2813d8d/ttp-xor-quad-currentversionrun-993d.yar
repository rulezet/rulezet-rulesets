rule TTP_XOR_QUAD_CurrentVersionRun_993d {
  strings:
    $key_993d = { ca 52 [2] ee 5c [2] c5 70 [2] eb 52 [2] ff 49 [2] f0 53 [2] ee 4e [2] ec 4f [2] f7 49 [2] eb 4e [2] f7 61 }

  condition:
    any of them
}