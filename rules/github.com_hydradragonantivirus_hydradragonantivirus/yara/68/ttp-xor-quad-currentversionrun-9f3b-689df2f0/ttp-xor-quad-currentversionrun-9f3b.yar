rule TTP_XOR_QUAD_CurrentVersionRun_9f3b {
  strings:
    $key_9f3b = { cc 54 [2] e8 5a [2] c3 76 [2] ed 54 [2] f9 4f [2] f6 55 [2] e8 48 [2] ea 49 [2] f1 4f [2] ed 48 [2] f1 67 }

  condition:
    any of them
}