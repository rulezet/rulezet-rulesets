rule TTP_XOR_QUAD_CurrentVersionRun_f1bb {
  strings:
    $key_f1bb = { a2 d4 [2] 86 da [2] ad f6 [2] 83 d4 [2] 97 cf [2] 98 d5 [2] 86 c8 [2] 84 c9 [2] 9f cf [2] 83 c8 [2] 9f e7 }

  condition:
    any of them
}