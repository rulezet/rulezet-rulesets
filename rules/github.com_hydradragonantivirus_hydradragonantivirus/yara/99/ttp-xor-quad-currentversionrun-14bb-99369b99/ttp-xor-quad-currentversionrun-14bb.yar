rule TTP_XOR_QUAD_CurrentVersionRun_14bb {
  strings:
    $key_14bb = { 47 d4 [2] 63 da [2] 48 f6 [2] 66 d4 [2] 72 cf [2] 7d d5 [2] 63 c8 [2] 61 c9 [2] 7a cf [2] 66 c8 [2] 7a e7 }

  condition:
    any of them
}