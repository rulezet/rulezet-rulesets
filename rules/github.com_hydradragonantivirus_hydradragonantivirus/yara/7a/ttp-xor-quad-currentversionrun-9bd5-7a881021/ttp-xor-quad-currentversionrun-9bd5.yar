rule TTP_XOR_QUAD_CurrentVersionRun_9bd5 {
  strings:
    $key_9bd5 = { c8 ba [2] ec b4 [2] c7 98 [2] e9 ba [2] fd a1 [2] f2 bb [2] ec a6 [2] ee a7 [2] f5 a1 [2] e9 a6 [2] f5 89 }

  condition:
    any of them
}