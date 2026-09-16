rule TTP_XOR_QUAD_CurrentVersionRun_9cd2 {
  strings:
    $key_9cd2 = { cf bd [2] eb b3 [2] c0 9f [2] ee bd [2] fa a6 [2] f5 bc [2] eb a1 [2] e9 a0 [2] f2 a6 [2] ee a1 [2] f2 8e }

  condition:
    any of them
}