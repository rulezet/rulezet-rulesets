rule TTP_XOR_QUAD_CurrentVersionRun_9ccb {
  strings:
    $key_9ccb = { cf a4 [2] eb aa [2] c0 86 [2] ee a4 [2] fa bf [2] f5 a5 [2] eb b8 [2] e9 b9 [2] f2 bf [2] ee b8 [2] f2 97 }

  condition:
    any of them
}