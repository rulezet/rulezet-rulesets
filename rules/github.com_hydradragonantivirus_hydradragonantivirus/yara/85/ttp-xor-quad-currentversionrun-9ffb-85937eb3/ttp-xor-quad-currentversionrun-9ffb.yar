rule TTP_XOR_QUAD_CurrentVersionRun_9ffb {
  strings:
    $key_9ffb = { cc 94 [2] e8 9a [2] c3 b6 [2] ed 94 [2] f9 8f [2] f6 95 [2] e8 88 [2] ea 89 [2] f1 8f [2] ed 88 [2] f1 a7 }

  condition:
    any of them
}