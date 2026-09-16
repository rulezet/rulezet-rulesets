rule TTP_XOR_QUAD_CurrentVersionRun_8357 {
  strings:
    $key_8357 = { d0 38 [2] f4 36 [2] df 1a [2] f1 38 [2] e5 23 [2] ea 39 [2] f4 24 [2] f6 25 [2] ed 23 [2] f1 24 [2] ed 0b }

  condition:
    any of them
}