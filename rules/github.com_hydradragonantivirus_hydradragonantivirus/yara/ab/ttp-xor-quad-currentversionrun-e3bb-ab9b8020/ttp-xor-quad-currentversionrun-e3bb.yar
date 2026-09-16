rule TTP_XOR_QUAD_CurrentVersionRun_e3bb {
  strings:
    $key_e3bb = { b0 d4 [2] 94 da [2] bf f6 [2] 91 d4 [2] 85 cf [2] 8a d5 [2] 94 c8 [2] 96 c9 [2] 8d cf [2] 91 c8 [2] 8d e7 }

  condition:
    any of them
}