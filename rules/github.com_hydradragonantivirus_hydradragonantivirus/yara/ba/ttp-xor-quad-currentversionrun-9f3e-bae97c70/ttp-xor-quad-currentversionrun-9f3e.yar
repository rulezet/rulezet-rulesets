rule TTP_XOR_QUAD_CurrentVersionRun_9f3e {
  strings:
    $key_9f3e = { cc 51 [2] e8 5f [2] c3 73 [2] ed 51 [2] f9 4a [2] f6 50 [2] e8 4d [2] ea 4c [2] f1 4a [2] ed 4d [2] f1 62 }

  condition:
    any of them
}