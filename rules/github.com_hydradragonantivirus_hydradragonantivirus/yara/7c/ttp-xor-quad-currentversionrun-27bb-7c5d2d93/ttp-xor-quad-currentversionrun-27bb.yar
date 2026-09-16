rule TTP_XOR_QUAD_CurrentVersionRun_27bb {
  strings:
    $key_27bb = { 74 d4 [2] 50 da [2] 7b f6 [2] 55 d4 [2] 41 cf [2] 4e d5 [2] 50 c8 [2] 52 c9 [2] 49 cf [2] 55 c8 [2] 49 e7 }

  condition:
    any of them
}