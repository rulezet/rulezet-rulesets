rule TTP_XOR_QUAD_CurrentVersionRun_80db {
  strings:
    $key_80db = { d3 b4 [2] f7 ba [2] dc 96 [2] f2 b4 [2] e6 af [2] e9 b5 [2] f7 a8 [2] f5 a9 [2] ee af [2] f2 a8 [2] ee 87 }

  condition:
    any of them
}