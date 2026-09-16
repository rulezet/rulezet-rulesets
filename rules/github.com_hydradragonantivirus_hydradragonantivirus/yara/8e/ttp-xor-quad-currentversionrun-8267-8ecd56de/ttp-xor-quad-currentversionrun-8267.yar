rule TTP_XOR_QUAD_CurrentVersionRun_8267 {
  strings:
    $key_8267 = { d1 08 [2] f5 06 [2] de 2a [2] f0 08 [2] e4 13 [2] eb 09 [2] f5 14 [2] f7 15 [2] ec 13 [2] f0 14 [2] ec 3b }

  condition:
    any of them
}