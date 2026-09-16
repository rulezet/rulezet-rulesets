rule TTP_XOR_QUAD_CurrentVersionRun_9f35 {
  strings:
    $key_9f35 = { cc 5a [2] e8 54 [2] c3 78 [2] ed 5a [2] f9 41 [2] f6 5b [2] e8 46 [2] ea 47 [2] f1 41 [2] ed 46 [2] f1 69 }

  condition:
    any of them
}