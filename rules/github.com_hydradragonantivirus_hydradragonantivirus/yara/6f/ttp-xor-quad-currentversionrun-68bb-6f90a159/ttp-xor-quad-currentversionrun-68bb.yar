rule TTP_XOR_QUAD_CurrentVersionRun_68bb {
  strings:
    $key_68bb = { 3b d4 [2] 1f da [2] 34 f6 [2] 1a d4 [2] 0e cf [2] 01 d5 [2] 1f c8 [2] 1d c9 [2] 06 cf [2] 1a c8 [2] 06 e7 }

  condition:
    any of them
}