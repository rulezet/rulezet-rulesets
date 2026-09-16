rule TTP_XOR_QUAD_CurrentVersionRun_9f80 {
  strings:
    $key_9f80 = { cc ef [2] e8 e1 [2] c3 cd [2] ed ef [2] f9 f4 [2] f6 ee [2] e8 f3 [2] ea f2 [2] f1 f4 [2] ed f3 [2] f1 dc }

  condition:
    any of them
}