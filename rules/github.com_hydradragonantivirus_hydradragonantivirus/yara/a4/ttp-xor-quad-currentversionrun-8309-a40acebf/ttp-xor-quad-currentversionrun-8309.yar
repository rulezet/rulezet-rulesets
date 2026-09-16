rule TTP_XOR_QUAD_CurrentVersionRun_8309 {
  strings:
    $key_8309 = { d0 66 [2] f4 68 [2] df 44 [2] f1 66 [2] e5 7d [2] ea 67 [2] f4 7a [2] f6 7b [2] ed 7d [2] f1 7a [2] ed 55 }

  condition:
    any of them
}