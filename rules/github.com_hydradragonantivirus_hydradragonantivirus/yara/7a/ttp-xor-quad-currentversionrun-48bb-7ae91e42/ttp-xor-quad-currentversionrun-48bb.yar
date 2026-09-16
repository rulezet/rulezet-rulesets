rule TTP_XOR_QUAD_CurrentVersionRun_48bb {
  strings:
    $key_48bb = { 1b d4 [2] 3f da [2] 14 f6 [2] 3a d4 [2] 2e cf [2] 21 d5 [2] 3f c8 [2] 3d c9 [2] 26 cf [2] 3a c8 [2] 26 e7 }

  condition:
    any of them
}