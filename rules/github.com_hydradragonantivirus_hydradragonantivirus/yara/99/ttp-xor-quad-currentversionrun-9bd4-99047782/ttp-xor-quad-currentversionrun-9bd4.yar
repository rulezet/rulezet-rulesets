rule TTP_XOR_QUAD_CurrentVersionRun_9bd4 {
  strings:
    $key_9bd4 = { c8 bb [2] ec b5 [2] c7 99 [2] e9 bb [2] fd a0 [2] f2 ba [2] ec a7 [2] ee a6 [2] f5 a0 [2] e9 a7 [2] f5 88 }

  condition:
    any of them
}