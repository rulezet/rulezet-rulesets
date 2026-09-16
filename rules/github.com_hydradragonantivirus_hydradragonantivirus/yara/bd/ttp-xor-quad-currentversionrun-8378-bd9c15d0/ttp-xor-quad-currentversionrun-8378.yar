rule TTP_XOR_QUAD_CurrentVersionRun_8378 {
  strings:
    $key_8378 = { d0 17 [2] f4 19 [2] df 35 [2] f1 17 [2] e5 0c [2] ea 16 [2] f4 0b [2] f6 0a [2] ed 0c [2] f1 0b [2] ed 24 }

  condition:
    any of them
}