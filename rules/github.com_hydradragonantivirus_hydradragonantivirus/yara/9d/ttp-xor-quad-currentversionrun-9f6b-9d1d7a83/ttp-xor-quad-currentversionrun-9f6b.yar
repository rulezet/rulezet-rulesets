rule TTP_XOR_QUAD_CurrentVersionRun_9f6b {
  strings:
    $key_9f6b = { cc 04 [2] e8 0a [2] c3 26 [2] ed 04 [2] f9 1f [2] f6 05 [2] e8 18 [2] ea 19 [2] f1 1f [2] ed 18 [2] f1 37 }

  condition:
    any of them
}