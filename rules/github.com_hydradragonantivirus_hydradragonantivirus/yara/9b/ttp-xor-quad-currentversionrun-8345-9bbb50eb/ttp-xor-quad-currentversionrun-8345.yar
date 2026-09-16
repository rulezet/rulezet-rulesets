rule TTP_XOR_QUAD_CurrentVersionRun_8345 {
  strings:
    $key_8345 = { d0 2a [2] f4 24 [2] df 08 [2] f1 2a [2] e5 31 [2] ea 2b [2] f4 36 [2] f6 37 [2] ed 31 [2] f1 36 [2] ed 19 }

  condition:
    any of them
}