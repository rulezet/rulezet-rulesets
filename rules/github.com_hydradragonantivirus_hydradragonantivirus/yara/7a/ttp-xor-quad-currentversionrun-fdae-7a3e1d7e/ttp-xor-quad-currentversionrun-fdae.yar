rule TTP_XOR_QUAD_CurrentVersionRun_fdae {
  strings:
    $key_fdae = { ae c1 [2] 8a cf [2] a1 e3 [2] 8f c1 [2] 9b da [2] 94 c0 [2] 8a dd [2] 88 dc [2] 93 da [2] 8f dd [2] 93 f2 }

  condition:
    any of them
}