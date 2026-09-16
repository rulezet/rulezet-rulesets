rule TTP_XOR_QUAD_CurrentVersionRun_85df {
  strings:
    $key_85df = { d6 b0 [2] f2 be [2] d9 92 [2] f7 b0 [2] e3 ab [2] ec b1 [2] f2 ac [2] f0 ad [2] eb ab [2] f7 ac [2] eb 83 }

  condition:
    any of them
}