rule TTP_XOR_QUAD_CurrentVersionRun_38bb {
  strings:
    $key_38bb = { 6b d4 [2] 4f da [2] 64 f6 [2] 4a d4 [2] 5e cf [2] 51 d5 [2] 4f c8 [2] 4d c9 [2] 56 cf [2] 4a c8 [2] 56 e7 }

  condition:
    any of them
}