rule TTP_XOR_QUAD_CurrentVersionRun_9f0d {
  strings:
    $key_9f0d = { cc 62 [2] e8 6c [2] c3 40 [2] ed 62 [2] f9 79 [2] f6 63 [2] e8 7e [2] ea 7f [2] f1 79 [2] ed 7e [2] f1 51 }

  condition:
    any of them
}