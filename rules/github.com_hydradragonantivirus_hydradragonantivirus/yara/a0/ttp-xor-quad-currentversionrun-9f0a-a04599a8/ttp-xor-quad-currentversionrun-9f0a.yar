rule TTP_XOR_QUAD_CurrentVersionRun_9f0a {
  strings:
    $key_9f0a = { cc 65 [2] e8 6b [2] c3 47 [2] ed 65 [2] f9 7e [2] f6 64 [2] e8 79 [2] ea 78 [2] f1 7e [2] ed 79 [2] f1 56 }

  condition:
    any of them
}