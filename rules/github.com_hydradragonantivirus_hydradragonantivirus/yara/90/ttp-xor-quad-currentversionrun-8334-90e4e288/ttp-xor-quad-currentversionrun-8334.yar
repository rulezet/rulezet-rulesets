rule TTP_XOR_QUAD_CurrentVersionRun_8334 {
  strings:
    $key_8334 = { d0 5b [2] f4 55 [2] df 79 [2] f1 5b [2] e5 40 [2] ea 5a [2] f4 47 [2] f6 46 [2] ed 40 [2] f1 47 [2] ed 68 }

  condition:
    any of them
}