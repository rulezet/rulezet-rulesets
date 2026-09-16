rule TTP_XOR_QUAD_CurrentVersionRun_9bd1 {
  strings:
    $key_9bd1 = { c8 be [2] ec b0 [2] c7 9c [2] e9 be [2] fd a5 [2] f2 bf [2] ec a2 [2] ee a3 [2] f5 a5 [2] e9 a2 [2] f5 8d }

  condition:
    any of them
}