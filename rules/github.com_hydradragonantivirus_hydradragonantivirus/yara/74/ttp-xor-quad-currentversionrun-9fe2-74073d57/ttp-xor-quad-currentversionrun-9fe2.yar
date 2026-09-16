rule TTP_XOR_QUAD_CurrentVersionRun_9fe2 {
  strings:
    $key_9fe2 = { cc 8d [2] e8 83 [2] c3 af [2] ed 8d [2] f9 96 [2] f6 8c [2] e8 91 [2] ea 90 [2] f1 96 [2] ed 91 [2] f1 be }

  condition:
    any of them
}