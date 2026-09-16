rule TTP_XOR_QUAD_CurrentVersionRun_824d {
  strings:
    $key_824d = { d1 22 [2] f5 2c [2] de 00 [2] f0 22 [2] e4 39 [2] eb 23 [2] f5 3e [2] f7 3f [2] ec 39 [2] f0 3e [2] ec 11 }

  condition:
    any of them
}