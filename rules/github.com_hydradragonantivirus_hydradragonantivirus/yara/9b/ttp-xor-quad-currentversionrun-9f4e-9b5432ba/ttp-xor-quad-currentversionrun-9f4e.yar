rule TTP_XOR_QUAD_CurrentVersionRun_9f4e {
  strings:
    $key_9f4e = { cc 21 [2] e8 2f [2] c3 03 [2] ed 21 [2] f9 3a [2] f6 20 [2] e8 3d [2] ea 3c [2] f1 3a [2] ed 3d [2] f1 12 }

  condition:
    any of them
}