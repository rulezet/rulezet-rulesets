rule TTP_XOR_QUAD_CurrentVersionRun_9f6d {
  strings:
    $key_9f6d = { cc 02 [2] e8 0c [2] c3 20 [2] ed 02 [2] f9 19 [2] f6 03 [2] e8 1e [2] ea 1f [2] f1 19 [2] ed 1e [2] f1 31 }

  condition:
    any of them
}