rule TTP_XOR_QUAD_CurrentVersionRun_9fae {
  strings:
    $key_9fae = { cc c1 [2] e8 cf [2] c3 e3 [2] ed c1 [2] f9 da [2] f6 c0 [2] e8 dd [2] ea dc [2] f1 da [2] ed dd [2] f1 f2 }

  condition:
    any of them
}