rule TTP_XOR_QUAD_CurrentVersionRun_9f98 {
  strings:
    $key_9f98 = { cc f7 [2] e8 f9 [2] c3 d5 [2] ed f7 [2] f9 ec [2] f6 f6 [2] e8 eb [2] ea ea [2] f1 ec [2] ed eb [2] f1 c4 }

  condition:
    any of them
}