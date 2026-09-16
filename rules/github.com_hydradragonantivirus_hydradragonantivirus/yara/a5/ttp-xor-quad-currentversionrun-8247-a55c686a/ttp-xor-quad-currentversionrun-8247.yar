rule TTP_XOR_QUAD_CurrentVersionRun_8247 {
  strings:
    $key_8247 = { d1 28 [2] f5 26 [2] de 0a [2] f0 28 [2] e4 33 [2] eb 29 [2] f5 34 [2] f7 35 [2] ec 33 [2] f0 34 [2] ec 1b }

  condition:
    any of them
}