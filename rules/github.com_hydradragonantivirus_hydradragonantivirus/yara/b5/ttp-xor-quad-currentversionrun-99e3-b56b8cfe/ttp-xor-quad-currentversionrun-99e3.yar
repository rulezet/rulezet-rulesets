rule TTP_XOR_QUAD_CurrentVersionRun_99e3 {
  strings:
    $key_99e3 = { ca 8c [2] ee 82 [2] c5 ae [2] eb 8c [2] ff 97 [2] f0 8d [2] ee 90 [2] ec 91 [2] f7 97 [2] eb 90 [2] f7 bf }

  condition:
    any of them
}