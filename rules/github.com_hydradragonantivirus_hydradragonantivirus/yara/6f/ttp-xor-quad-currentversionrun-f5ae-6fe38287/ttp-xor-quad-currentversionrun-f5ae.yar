rule TTP_XOR_QUAD_CurrentVersionRun_f5ae {
  strings:
    $key_f5ae = { a6 c1 [2] 82 cf [2] a9 e3 [2] 87 c1 [2] 93 da [2] 9c c0 [2] 82 dd [2] 80 dc [2] 9b da [2] 87 dd [2] 9b f2 }

  condition:
    any of them
}