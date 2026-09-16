rule TTP_XOR_QUAD_CurrentVersionRun_15ae {
  strings:
    $key_15ae = { 46 c1 [2] 62 cf [2] 49 e3 [2] 67 c1 [2] 73 da [2] 7c c0 [2] 62 dd [2] 60 dc [2] 7b da [2] 67 dd [2] 7b f2 }

  condition:
    any of them
}