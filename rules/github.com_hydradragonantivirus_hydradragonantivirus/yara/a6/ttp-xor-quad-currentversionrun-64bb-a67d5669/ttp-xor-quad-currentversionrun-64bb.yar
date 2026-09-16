rule TTP_XOR_QUAD_CurrentVersionRun_64bb {
  strings:
    $key_64bb = { 37 d4 [2] 13 da [2] 38 f6 [2] 16 d4 [2] 02 cf [2] 0d d5 [2] 13 c8 [2] 11 c9 [2] 0a cf [2] 16 c8 [2] 0a e7 }

  condition:
    any of them
}