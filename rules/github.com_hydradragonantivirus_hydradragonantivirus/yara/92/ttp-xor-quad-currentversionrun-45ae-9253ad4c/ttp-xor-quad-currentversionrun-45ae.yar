rule TTP_XOR_QUAD_CurrentVersionRun_45ae {
  strings:
    $key_45ae = { 16 c1 [2] 32 cf [2] 19 e3 [2] 37 c1 [2] 23 da [2] 2c c0 [2] 32 dd [2] 30 dc [2] 2b da [2] 37 dd [2] 2b f2 }

  condition:
    any of them
}