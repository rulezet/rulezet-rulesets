rule TTP_XOR_QUAD_CurrentVersionRun_9f30 {
  strings:
    $key_9f30 = { cc 5f [2] e8 51 [2] c3 7d [2] ed 5f [2] f9 44 [2] f6 5e [2] e8 43 [2] ea 42 [2] f1 44 [2] ed 43 [2] f1 6c }

  condition:
    any of them
}