rule TTP_XOR_QUAD_CurrentVersionRun_8254 {
  strings:
    $key_8254 = { d1 3b [2] f5 35 [2] de 19 [2] f0 3b [2] e4 20 [2] eb 3a [2] f5 27 [2] f7 26 [2] ec 20 [2] f0 27 [2] ec 08 }

  condition:
    any of them
}