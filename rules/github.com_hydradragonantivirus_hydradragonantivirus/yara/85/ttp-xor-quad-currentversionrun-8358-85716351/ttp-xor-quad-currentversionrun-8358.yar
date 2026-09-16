rule TTP_XOR_QUAD_CurrentVersionRun_8358 {
  strings:
    $key_8358 = { d0 37 [2] f4 39 [2] df 15 [2] f1 37 [2] e5 2c [2] ea 36 [2] f4 2b [2] f6 2a [2] ed 2c [2] f1 2b [2] ed 04 }

  condition:
    any of them
}