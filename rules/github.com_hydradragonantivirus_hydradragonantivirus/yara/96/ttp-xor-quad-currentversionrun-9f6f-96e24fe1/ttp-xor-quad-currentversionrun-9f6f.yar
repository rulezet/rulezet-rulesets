rule TTP_XOR_QUAD_CurrentVersionRun_9f6f {
  strings:
    $key_9f6f = { cc 00 [2] e8 0e [2] c3 22 [2] ed 00 [2] f9 1b [2] f6 01 [2] e8 1c [2] ea 1d [2] f1 1b [2] ed 1c [2] f1 33 }

  condition:
    any of them
}