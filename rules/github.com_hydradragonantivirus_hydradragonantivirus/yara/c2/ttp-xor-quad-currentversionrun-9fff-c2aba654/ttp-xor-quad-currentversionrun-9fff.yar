rule TTP_XOR_QUAD_CurrentVersionRun_9fff {
  strings:
    $key_9fff = { cc 90 [2] e8 9e [2] c3 b2 [2] ed 90 [2] f9 8b [2] f6 91 [2] e8 8c [2] ea 8d [2] f1 8b [2] ed 8c [2] f1 a3 }

  condition:
    any of them
}