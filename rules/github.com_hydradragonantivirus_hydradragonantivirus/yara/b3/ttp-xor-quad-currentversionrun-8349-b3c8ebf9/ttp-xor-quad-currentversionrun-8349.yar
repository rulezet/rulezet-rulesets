rule TTP_XOR_QUAD_CurrentVersionRun_8349 {
  strings:
    $key_8349 = { d0 26 [2] f4 28 [2] df 04 [2] f1 26 [2] e5 3d [2] ea 27 [2] f4 3a [2] f6 3b [2] ed 3d [2] f1 3a [2] ed 15 }

  condition:
    any of them
}