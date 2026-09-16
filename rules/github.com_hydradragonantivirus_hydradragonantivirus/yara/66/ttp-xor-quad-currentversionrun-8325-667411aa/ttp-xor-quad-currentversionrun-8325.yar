rule TTP_XOR_QUAD_CurrentVersionRun_8325 {
  strings:
    $key_8325 = { d0 4a [2] f4 44 [2] df 68 [2] f1 4a [2] e5 51 [2] ea 4b [2] f4 56 [2] f6 57 [2] ed 51 [2] f1 56 [2] ed 79 }

  condition:
    any of them
}