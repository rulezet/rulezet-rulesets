rule TTP_XOR_QUAD_CurrentVersionRun_9f34 {
  strings:
    $key_9f34 = { cc 5b [2] e8 55 [2] c3 79 [2] ed 5b [2] f9 40 [2] f6 5a [2] e8 47 [2] ea 46 [2] f1 40 [2] ed 47 [2] f1 68 }

  condition:
    any of them
}