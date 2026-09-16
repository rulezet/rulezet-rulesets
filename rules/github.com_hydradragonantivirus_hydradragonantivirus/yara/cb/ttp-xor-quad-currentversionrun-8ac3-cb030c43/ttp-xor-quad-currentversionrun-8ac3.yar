rule TTP_XOR_QUAD_CurrentVersionRun_8ac3 {
  strings:
    $key_8ac3 = { d9 ac [2] fd a2 [2] d6 8e [2] f8 ac [2] ec b7 [2] e3 ad [2] fd b0 [2] ff b1 [2] e4 b7 [2] f8 b0 [2] e4 9f }

  condition:
    any of them
}