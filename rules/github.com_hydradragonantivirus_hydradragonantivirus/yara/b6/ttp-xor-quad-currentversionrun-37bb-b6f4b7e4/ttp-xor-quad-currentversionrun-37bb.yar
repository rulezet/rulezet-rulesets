rule TTP_XOR_QUAD_CurrentVersionRun_37bb {
  strings:
    $key_37bb = { 64 d4 [2] 40 da [2] 6b f6 [2] 45 d4 [2] 51 cf [2] 5e d5 [2] 40 c8 [2] 42 c9 [2] 59 cf [2] 45 c8 [2] 59 e7 }

  condition:
    any of them
}