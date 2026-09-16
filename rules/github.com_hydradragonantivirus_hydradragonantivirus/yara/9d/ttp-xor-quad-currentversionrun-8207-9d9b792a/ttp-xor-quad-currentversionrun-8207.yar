rule TTP_XOR_QUAD_CurrentVersionRun_8207 {
  strings:
    $key_8207 = { d1 68 [2] f5 66 [2] de 4a [2] f0 68 [2] e4 73 [2] eb 69 [2] f5 74 [2] f7 75 [2] ec 73 [2] f0 74 [2] ec 5b }

  condition:
    any of them
}