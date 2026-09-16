rule TTP_XOR_QUAD_CurrentVersionRun_9f4a {
  strings:
    $key_9f4a = { cc 25 [2] e8 2b [2] c3 07 [2] ed 25 [2] f9 3e [2] f6 24 [2] e8 39 [2] ea 38 [2] f1 3e [2] ed 39 [2] f1 16 }

  condition:
    any of them
}