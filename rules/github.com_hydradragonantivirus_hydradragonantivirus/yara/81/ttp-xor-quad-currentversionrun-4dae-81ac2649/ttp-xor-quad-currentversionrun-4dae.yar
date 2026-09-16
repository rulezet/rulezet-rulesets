rule TTP_XOR_QUAD_CurrentVersionRun_4dae {
  strings:
    $key_4dae = { 1e c1 [2] 3a cf [2] 11 e3 [2] 3f c1 [2] 2b da [2] 24 c0 [2] 3a dd [2] 38 dc [2] 23 da [2] 3f dd [2] 23 f2 }

  condition:
    any of them
}