rule TTP_XOR_QUAD_CurrentVersionRun_9fe3 {
  strings:
    $key_9fe3 = { cc 8c [2] e8 82 [2] c3 ae [2] ed 8c [2] f9 97 [2] f6 8d [2] e8 90 [2] ea 91 [2] f1 97 [2] ed 90 [2] f1 bf }

  condition:
    any of them
}