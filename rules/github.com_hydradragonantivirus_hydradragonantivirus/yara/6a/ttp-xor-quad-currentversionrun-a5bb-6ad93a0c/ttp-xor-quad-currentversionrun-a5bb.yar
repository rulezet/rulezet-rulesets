rule TTP_XOR_QUAD_CurrentVersionRun_a5bb {
  strings:
    $key_a5bb = { f6 d4 [2] d2 da [2] f9 f6 [2] d7 d4 [2] c3 cf [2] cc d5 [2] d2 c8 [2] d0 c9 [2] cb cf [2] d7 c8 [2] cb e7 }

  condition:
    any of them
}