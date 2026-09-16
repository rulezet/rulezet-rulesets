rule TTP_XOR_QUAD_CurrentVersionRun_9f71 {
  strings:
    $key_9f71 = { cc 1e [2] e8 10 [2] c3 3c [2] ed 1e [2] f9 05 [2] f6 1f [2] e8 02 [2] ea 03 [2] f1 05 [2] ed 02 [2] f1 2d }

  condition:
    any of them
}