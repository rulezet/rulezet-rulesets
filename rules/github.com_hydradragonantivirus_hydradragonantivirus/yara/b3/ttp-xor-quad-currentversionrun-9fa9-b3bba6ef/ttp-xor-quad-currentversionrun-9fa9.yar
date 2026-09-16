rule TTP_XOR_QUAD_CurrentVersionRun_9fa9 {
  strings:
    $key_9fa9 = { cc c6 [2] e8 c8 [2] c3 e4 [2] ed c6 [2] f9 dd [2] f6 c7 [2] e8 da [2] ea db [2] f1 dd [2] ed da [2] f1 f5 }

  condition:
    any of them
}