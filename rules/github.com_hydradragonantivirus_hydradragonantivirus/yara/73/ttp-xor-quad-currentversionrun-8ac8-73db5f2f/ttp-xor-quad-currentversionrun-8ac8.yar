rule TTP_XOR_QUAD_CurrentVersionRun_8ac8 {
  strings:
    $key_8ac8 = { d9 a7 [2] fd a9 [2] d6 85 [2] f8 a7 [2] ec bc [2] e3 a6 [2] fd bb [2] ff ba [2] e4 bc [2] f8 bb [2] e4 94 }

  condition:
    any of them
}