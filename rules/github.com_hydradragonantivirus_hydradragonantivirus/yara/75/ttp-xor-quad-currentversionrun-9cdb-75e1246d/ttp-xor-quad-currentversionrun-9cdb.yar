rule TTP_XOR_QUAD_CurrentVersionRun_9cdb {
  strings:
    $key_9cdb = { cf b4 [2] eb ba [2] c0 96 [2] ee b4 [2] fa af [2] f5 b5 [2] eb a8 [2] e9 a9 [2] f2 af [2] ee a8 [2] f2 87 }

  condition:
    any of them
}