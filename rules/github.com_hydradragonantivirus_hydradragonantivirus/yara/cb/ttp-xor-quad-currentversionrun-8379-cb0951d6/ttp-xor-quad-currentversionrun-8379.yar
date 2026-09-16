rule TTP_XOR_QUAD_CurrentVersionRun_8379 {
  strings:
    $key_8379 = { d0 16 [2] f4 18 [2] df 34 [2] f1 16 [2] e5 0d [2] ea 17 [2] f4 0a [2] f6 0b [2] ed 0d [2] f1 0a [2] ed 25 }

  condition:
    any of them
}