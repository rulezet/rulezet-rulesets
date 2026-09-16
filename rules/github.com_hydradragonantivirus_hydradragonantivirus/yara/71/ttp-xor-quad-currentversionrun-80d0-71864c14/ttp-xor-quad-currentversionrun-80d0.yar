rule TTP_XOR_QUAD_CurrentVersionRun_80d0 {
  strings:
    $key_80d0 = { d3 bf [2] f7 b1 [2] dc 9d [2] f2 bf [2] e6 a4 [2] e9 be [2] f7 a3 [2] f5 a2 [2] ee a4 [2] f2 a3 [2] ee 8c }

  condition:
    any of them
}