rule TTP_XOR_QUAD_CurrentVersionRun_9f6c {
  strings:
    $key_9f6c = { cc 03 [2] e8 0d [2] c3 21 [2] ed 03 [2] f9 18 [2] f6 02 [2] e8 1f [2] ea 1e [2] f1 18 [2] ed 1f [2] f1 30 }

  condition:
    any of them
}