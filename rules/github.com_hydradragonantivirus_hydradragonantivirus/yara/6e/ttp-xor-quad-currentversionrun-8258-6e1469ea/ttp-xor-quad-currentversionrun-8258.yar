rule TTP_XOR_QUAD_CurrentVersionRun_8258 {
  strings:
    $key_8258 = { d1 37 [2] f5 39 [2] de 15 [2] f0 37 [2] e4 2c [2] eb 36 [2] f5 2b [2] f7 2a [2] ec 2c [2] f0 2b [2] ec 04 }

  condition:
    any of them
}