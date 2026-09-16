rule TTP_XOR_QUAD_CurrentVersionRun_9f85 {
  strings:
    $key_9f85 = { cc ea [2] e8 e4 [2] c3 c8 [2] ed ea [2] f9 f1 [2] f6 eb [2] e8 f6 [2] ea f7 [2] f1 f1 [2] ed f6 [2] f1 d9 }

  condition:
    any of them
}