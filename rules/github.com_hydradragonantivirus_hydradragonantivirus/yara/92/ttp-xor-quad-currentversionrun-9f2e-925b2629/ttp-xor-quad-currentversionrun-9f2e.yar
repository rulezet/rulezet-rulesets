rule TTP_XOR_QUAD_CurrentVersionRun_9f2e {
  strings:
    $key_9f2e = { cc 41 [2] e8 4f [2] c3 63 [2] ed 41 [2] f9 5a [2] f6 40 [2] e8 5d [2] ea 5c [2] f1 5a [2] ed 5d [2] f1 72 }

  condition:
    any of them
}