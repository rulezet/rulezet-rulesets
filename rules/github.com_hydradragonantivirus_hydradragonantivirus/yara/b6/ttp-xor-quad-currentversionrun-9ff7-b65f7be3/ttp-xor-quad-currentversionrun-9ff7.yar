rule TTP_XOR_QUAD_CurrentVersionRun_9ff7 {
  strings:
    $key_9ff7 = { cc 98 [2] e8 96 [2] c3 ba [2] ed 98 [2] f9 83 [2] f6 99 [2] e8 84 [2] ea 85 [2] f1 83 [2] ed 84 [2] f1 ab }

  condition:
    any of them
}