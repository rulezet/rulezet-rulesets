rule TTP_XOR_QUAD_CurrentVersionRun_9cd0 {
  strings:
    $key_9cd0 = { cf bf [2] eb b1 [2] c0 9d [2] ee bf [2] fa a4 [2] f5 be [2] eb a3 [2] e9 a2 [2] f2 a4 [2] ee a3 [2] f2 8c }

  condition:
    any of them
}