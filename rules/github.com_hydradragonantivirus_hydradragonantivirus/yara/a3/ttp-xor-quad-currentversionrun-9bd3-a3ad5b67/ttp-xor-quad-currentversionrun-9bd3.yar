rule TTP_XOR_QUAD_CurrentVersionRun_9bd3 {
  strings:
    $key_9bd3 = { c8 bc [2] ec b2 [2] c7 9e [2] e9 bc [2] fd a7 [2] f2 bd [2] ec a0 [2] ee a1 [2] f5 a7 [2] e9 a0 [2] f5 8f }

  condition:
    any of them
}