rule TTP_XOR_QUAD_CurrentVersionRun_9fed {
  strings:
    $key_9fed = { cc 82 [2] e8 8c [2] c3 a0 [2] ed 82 [2] f9 99 [2] f6 83 [2] e8 9e [2] ea 9f [2] f1 99 [2] ed 9e [2] f1 b1 }

  condition:
    any of them
}