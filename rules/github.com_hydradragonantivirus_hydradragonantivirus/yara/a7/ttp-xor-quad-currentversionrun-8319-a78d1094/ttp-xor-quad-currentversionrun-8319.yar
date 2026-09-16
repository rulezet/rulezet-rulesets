rule TTP_XOR_QUAD_CurrentVersionRun_8319 {
  strings:
    $key_8319 = { d0 76 [2] f4 78 [2] df 54 [2] f1 76 [2] e5 6d [2] ea 77 [2] f4 6a [2] f6 6b [2] ed 6d [2] f1 6a [2] ed 45 }

  condition:
    any of them
}