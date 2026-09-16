rule TTP_XOR_QUAD_CurrentVersionRun_80dc {
  strings:
    $key_80dc = { d3 b3 [2] f7 bd [2] dc 91 [2] f2 b3 [2] e6 a8 [2] e9 b2 [2] f7 af [2] f5 ae [2] ee a8 [2] f2 af [2] ee 80 }

  condition:
    any of them
}