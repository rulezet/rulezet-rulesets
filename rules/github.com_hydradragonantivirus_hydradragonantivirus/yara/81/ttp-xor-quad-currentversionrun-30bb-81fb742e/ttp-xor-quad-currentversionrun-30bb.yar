rule TTP_XOR_QUAD_CurrentVersionRun_30bb {
  strings:
    $key_30bb = { 63 d4 [2] 47 da [2] 6c f6 [2] 42 d4 [2] 56 cf [2] 59 d5 [2] 47 c8 [2] 45 c9 [2] 5e cf [2] 42 c8 [2] 5e e7 }

  condition:
    any of them
}