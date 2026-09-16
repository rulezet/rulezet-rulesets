rule TTP_XOR_QUAD_CurrentVersionRun_9f2a {
  strings:
    $key_9f2a = { cc 45 [2] e8 4b [2] c3 67 [2] ed 45 [2] f9 5e [2] f6 44 [2] e8 59 [2] ea 58 [2] f1 5e [2] ed 59 [2] f1 76 }

  condition:
    any of them
}