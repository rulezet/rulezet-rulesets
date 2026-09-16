rule TTP_XOR_QUAD_CurrentVersionRun_9f7f {
  strings:
    $key_9f7f = { cc 10 [2] e8 1e [2] c3 32 [2] ed 10 [2] f9 0b [2] f6 11 [2] e8 0c [2] ea 0d [2] f1 0b [2] ed 0c [2] f1 23 }

  condition:
    any of them
}