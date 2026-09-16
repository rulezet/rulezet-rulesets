rule TTP_XOR_QUAD_CurrentVersionRun_9f21 {
  strings:
    $key_9f21 = { cc 4e [2] e8 40 [2] c3 6c [2] ed 4e [2] f9 55 [2] f6 4f [2] e8 52 [2] ea 53 [2] f1 55 [2] ed 52 [2] f1 7d }

  condition:
    any of them
}