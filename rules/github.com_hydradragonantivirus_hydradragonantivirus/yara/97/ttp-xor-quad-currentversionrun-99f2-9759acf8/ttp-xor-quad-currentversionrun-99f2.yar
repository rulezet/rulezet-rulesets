rule TTP_XOR_QUAD_CurrentVersionRun_99f2 {
  strings:
    $key_99f2 = { ca 9d [2] ee 93 [2] c5 bf [2] eb 9d [2] ff 86 [2] f0 9c [2] ee 81 [2] ec 80 [2] f7 86 [2] eb 81 [2] f7 ae }

  condition:
    any of them
}