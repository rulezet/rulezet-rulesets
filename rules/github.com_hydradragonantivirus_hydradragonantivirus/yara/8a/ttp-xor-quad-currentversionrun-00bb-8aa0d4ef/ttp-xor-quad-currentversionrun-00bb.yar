rule TTP_XOR_QUAD_CurrentVersionRun_00bb {
  strings:
    $key_00bb = { 53 d4 [2] 77 da [2] 5c f6 [2] 72 d4 [2] 66 cf [2] 69 d5 [2] 77 c8 [2] 75 c9 [2] 6e cf [2] 72 c8 [2] 6e e7 }

  condition:
    any of them
}