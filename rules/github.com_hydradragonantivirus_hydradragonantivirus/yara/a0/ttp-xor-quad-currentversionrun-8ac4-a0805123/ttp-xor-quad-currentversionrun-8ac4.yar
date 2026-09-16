rule TTP_XOR_QUAD_CurrentVersionRun_8ac4 {
  strings:
    $key_8ac4 = { d9 ab [2] fd a5 [2] d6 89 [2] f8 ab [2] ec b0 [2] e3 aa [2] fd b7 [2] ff b6 [2] e4 b0 [2] f8 b7 [2] e4 98 }

  condition:
    any of them
}