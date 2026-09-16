rule TTP_XOR_QUAD_CurrentVersionRun_8ac7 {
  strings:
    $key_8ac7 = { d9 a8 [2] fd a6 [2] d6 8a [2] f8 a8 [2] ec b3 [2] e3 a9 [2] fd b4 [2] ff b5 [2] e4 b3 [2] f8 b4 [2] e4 9b }

  condition:
    any of them
}