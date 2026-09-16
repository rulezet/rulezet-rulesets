rule TTP_XOR_QUAD_CurrentVersionRun_0dae {
  strings:
    $key_0dae = { 5e c1 [2] 7a cf [2] 51 e3 [2] 7f c1 [2] 6b da [2] 64 c0 [2] 7a dd [2] 78 dc [2] 63 da [2] 7f dd [2] 63 f2 }

  condition:
    any of them
}