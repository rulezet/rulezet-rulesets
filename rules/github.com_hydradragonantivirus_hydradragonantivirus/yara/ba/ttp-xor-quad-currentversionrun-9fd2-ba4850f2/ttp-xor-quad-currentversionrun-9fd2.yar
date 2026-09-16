rule TTP_XOR_QUAD_CurrentVersionRun_9fd2 {
  strings:
    $key_9fd2 = { cc bd [2] e8 b3 [2] c3 9f [2] ed bd [2] f9 a6 [2] f6 bc [2] e8 a1 [2] ea a0 [2] f1 a6 [2] ed a1 [2] f1 8e }

  condition:
    any of them
}