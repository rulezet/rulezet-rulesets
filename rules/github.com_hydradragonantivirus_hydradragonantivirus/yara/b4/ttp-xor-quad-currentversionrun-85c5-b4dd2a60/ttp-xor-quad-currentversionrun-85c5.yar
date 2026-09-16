rule TTP_XOR_QUAD_CurrentVersionRun_85c5 {
  strings:
    $key_85c5 = { d6 aa [2] f2 a4 [2] d9 88 [2] f7 aa [2] e3 b1 [2] ec ab [2] f2 b6 [2] f0 b7 [2] eb b1 [2] f7 b6 [2] eb 99 }

  condition:
    any of them
}