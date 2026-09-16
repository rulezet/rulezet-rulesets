rule TTP_XOR_QUAD_CurrentVersionRun_9f8a {
  strings:
    $key_9f8a = { cc e5 [2] e8 eb [2] c3 c7 [2] ed e5 [2] f9 fe [2] f6 e4 [2] e8 f9 [2] ea f8 [2] f1 fe [2] ed f9 [2] f1 d6 }

  condition:
    any of them
}