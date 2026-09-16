rule TTP_XOR_QUAD_CurrentVersionRun_9f59 {
  strings:
    $key_9f59 = { cc 36 [2] e8 38 [2] c3 14 [2] ed 36 [2] f9 2d [2] f6 37 [2] e8 2a [2] ea 2b [2] f1 2d [2] ed 2a [2] f1 05 }

  condition:
    any of them
}