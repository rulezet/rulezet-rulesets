rule TTP_XOR_QUAD_CurrentVersionRun_9ff6 {
  strings:
    $key_9ff6 = { cc 99 [2] e8 97 [2] c3 bb [2] ed 99 [2] f9 82 [2] f6 98 [2] e8 85 [2] ea 84 [2] f1 82 [2] ed 85 [2] f1 aa }

  condition:
    any of them
}