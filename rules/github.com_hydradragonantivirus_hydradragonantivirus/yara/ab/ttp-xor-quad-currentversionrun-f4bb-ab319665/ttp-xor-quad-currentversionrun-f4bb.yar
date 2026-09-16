rule TTP_XOR_QUAD_CurrentVersionRun_f4bb {
  strings:
    $key_f4bb = { a7 d4 [2] 83 da [2] a8 f6 [2] 86 d4 [2] 92 cf [2] 9d d5 [2] 83 c8 [2] 81 c9 [2] 9a cf [2] 86 c8 [2] 9a e7 }

  condition:
    any of them
}