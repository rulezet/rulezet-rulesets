rule TTP_XOR_QUAD_CurrentVersionRun_e5bb {
  strings:
    $key_e5bb = { b6 d4 [2] 92 da [2] b9 f6 [2] 97 d4 [2] 83 cf [2] 8c d5 [2] 92 c8 [2] 90 c9 [2] 8b cf [2] 97 c8 [2] 8b e7 }

  condition:
    any of them
}