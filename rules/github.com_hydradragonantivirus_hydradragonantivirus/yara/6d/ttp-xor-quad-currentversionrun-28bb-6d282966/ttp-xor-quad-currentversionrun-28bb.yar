rule TTP_XOR_QUAD_CurrentVersionRun_28bb {
  strings:
    $key_28bb = { 7b d4 [2] 5f da [2] 74 f6 [2] 5a d4 [2] 4e cf [2] 41 d5 [2] 5f c8 [2] 5d c9 [2] 46 cf [2] 5a c8 [2] 46 e7 }

  condition:
    any of them
}