rule TTP_XOR_QUAD_CurrentVersionRun_9fe0 {
  strings:
    $key_9fe0 = { cc 8f [2] e8 81 [2] c3 ad [2] ed 8f [2] f9 94 [2] f6 8e [2] e8 93 [2] ea 92 [2] f1 94 [2] ed 93 [2] f1 bc }

  condition:
    any of them
}