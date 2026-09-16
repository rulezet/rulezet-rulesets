rule TTP_XOR_QUAD_CurrentVersionRun_80ca {
  strings:
    $key_80ca = { d3 a5 [2] f7 ab [2] dc 87 [2] f2 a5 [2] e6 be [2] e9 a4 [2] f7 b9 [2] f5 b8 [2] ee be [2] f2 b9 [2] ee 96 }

  condition:
    any of them
}