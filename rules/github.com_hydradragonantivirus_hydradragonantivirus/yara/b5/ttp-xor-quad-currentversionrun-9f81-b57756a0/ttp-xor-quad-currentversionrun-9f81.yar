rule TTP_XOR_QUAD_CurrentVersionRun_9f81 {
  strings:
    $key_9f81 = { cc ee [2] e8 e0 [2] c3 cc [2] ed ee [2] f9 f5 [2] f6 ef [2] e8 f2 [2] ea f3 [2] f1 f5 [2] ed f2 [2] f1 dd }

  condition:
    any of them
}