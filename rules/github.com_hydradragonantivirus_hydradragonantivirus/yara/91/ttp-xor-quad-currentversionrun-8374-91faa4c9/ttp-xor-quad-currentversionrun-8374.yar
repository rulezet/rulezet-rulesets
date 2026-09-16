rule TTP_XOR_QUAD_CurrentVersionRun_8374 {
  strings:
    $key_8374 = { d0 1b [2] f4 15 [2] df 39 [2] f1 1b [2] e5 00 [2] ea 1a [2] f4 07 [2] f6 06 [2] ed 00 [2] f1 07 [2] ed 28 }

  condition:
    any of them
}