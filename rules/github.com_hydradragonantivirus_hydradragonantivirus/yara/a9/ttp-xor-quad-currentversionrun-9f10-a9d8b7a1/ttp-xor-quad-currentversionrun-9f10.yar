rule TTP_XOR_QUAD_CurrentVersionRun_9f10 {
  strings:
    $key_9f10 = { cc 7f [2] e8 71 [2] c3 5d [2] ed 7f [2] f9 64 [2] f6 7e [2] e8 63 [2] ea 62 [2] f1 64 [2] ed 63 [2] f1 4c }

  condition:
    any of them
}