rule TTP_XOR_QUAD_CurrentVersionRun_9bd6 {
  strings:
    $key_9bd6 = { c8 b9 [2] ec b7 [2] c7 9b [2] e9 b9 [2] fd a2 [2] f2 b8 [2] ec a5 [2] ee a4 [2] f5 a2 [2] e9 a5 [2] f5 8a }

  condition:
    any of them
}