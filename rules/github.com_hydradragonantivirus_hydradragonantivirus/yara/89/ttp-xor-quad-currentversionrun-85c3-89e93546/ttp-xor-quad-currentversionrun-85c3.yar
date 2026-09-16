rule TTP_XOR_QUAD_CurrentVersionRun_85c3 {
  strings:
    $key_85c3 = { d6 ac [2] f2 a2 [2] d9 8e [2] f7 ac [2] e3 b7 [2] ec ad [2] f2 b0 [2] f0 b1 [2] eb b7 [2] f7 b0 [2] eb 9f }

  condition:
    any of them
}