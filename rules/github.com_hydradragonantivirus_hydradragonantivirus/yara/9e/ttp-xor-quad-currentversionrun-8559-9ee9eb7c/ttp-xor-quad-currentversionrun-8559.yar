rule TTP_XOR_QUAD_CurrentVersionRun_8559 {
  strings:
    $key_8559 = { d6 36 [2] f2 38 [2] d9 14 [2] f7 36 [2] e3 2d [2] ec 37 [2] f2 2a [2] f0 2b [2] eb 2d [2] f7 2a [2] eb 05 }

  condition:
    any of them
}