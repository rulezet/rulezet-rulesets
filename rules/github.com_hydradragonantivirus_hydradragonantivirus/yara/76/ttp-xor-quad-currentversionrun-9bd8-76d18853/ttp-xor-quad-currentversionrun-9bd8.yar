rule TTP_XOR_QUAD_CurrentVersionRun_9bd8 {
  strings:
    $key_9bd8 = { c8 b7 [2] ec b9 [2] c7 95 [2] e9 b7 [2] fd ac [2] f2 b6 [2] ec ab [2] ee aa [2] f5 ac [2] e9 ab [2] f5 84 }

  condition:
    any of them
}