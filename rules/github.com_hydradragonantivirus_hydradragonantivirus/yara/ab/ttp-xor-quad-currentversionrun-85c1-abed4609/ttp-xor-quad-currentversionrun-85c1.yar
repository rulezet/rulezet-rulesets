rule TTP_XOR_QUAD_CurrentVersionRun_85c1 {
  strings:
    $key_85c1 = { d6 ae [2] f2 a0 [2] d9 8c [2] f7 ae [2] e3 b5 [2] ec af [2] f2 b2 [2] f0 b3 [2] eb b5 [2] f7 b2 [2] eb 9d }

  condition:
    any of them
}