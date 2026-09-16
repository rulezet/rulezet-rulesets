rule TTP_XOR_QUAD_CurrentVersionRun_9f3f {
  strings:
    $key_9f3f = { cc 50 [2] e8 5e [2] c3 72 [2] ed 50 [2] f9 4b [2] f6 51 [2] e8 4c [2] ea 4d [2] f1 4b [2] ed 4c [2] f1 63 }

  condition:
    any of them
}