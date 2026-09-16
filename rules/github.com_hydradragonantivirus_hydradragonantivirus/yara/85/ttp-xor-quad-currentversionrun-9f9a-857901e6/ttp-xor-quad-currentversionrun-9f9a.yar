rule TTP_XOR_QUAD_CurrentVersionRun_9f9a {
  strings:
    $key_9f9a = { cc f5 [2] e8 fb [2] c3 d7 [2] ed f5 [2] f9 ee [2] f6 f4 [2] e8 e9 [2] ea e8 [2] f1 ee [2] ed e9 [2] f1 c6 }

  condition:
    any of them
}