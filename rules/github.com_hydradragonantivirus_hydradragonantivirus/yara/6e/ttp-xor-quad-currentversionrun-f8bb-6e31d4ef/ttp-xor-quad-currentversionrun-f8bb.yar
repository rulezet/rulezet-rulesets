rule TTP_XOR_QUAD_CurrentVersionRun_f8bb {
  strings:
    $key_f8bb = { ab d4 [2] 8f da [2] a4 f6 [2] 8a d4 [2] 9e cf [2] 91 d5 [2] 8f c8 [2] 8d c9 [2] 96 cf [2] 8a c8 [2] 96 e7 }

  condition:
    any of them
}