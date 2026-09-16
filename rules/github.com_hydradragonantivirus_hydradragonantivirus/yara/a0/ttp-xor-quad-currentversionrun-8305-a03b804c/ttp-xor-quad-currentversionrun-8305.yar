rule TTP_XOR_QUAD_CurrentVersionRun_8305 {
  strings:
    $key_8305 = { d0 6a [2] f4 64 [2] df 48 [2] f1 6a [2] e5 71 [2] ea 6b [2] f4 76 [2] f6 77 [2] ed 71 [2] f1 76 [2] ed 59 }

  condition:
    any of them
}