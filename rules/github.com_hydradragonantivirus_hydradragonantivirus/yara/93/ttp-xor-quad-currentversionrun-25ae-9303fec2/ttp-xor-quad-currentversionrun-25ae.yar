rule TTP_XOR_QUAD_CurrentVersionRun_25ae {
  strings:
    $key_25ae = { 76 c1 [2] 52 cf [2] 79 e3 [2] 57 c1 [2] 43 da [2] 4c c0 [2] 52 dd [2] 50 dc [2] 4b da [2] 57 dd [2] 4b f2 }

  condition:
    any of them
}