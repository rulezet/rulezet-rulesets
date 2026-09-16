rule TTP_XOR_QUAD_CurrentVersionRun_a2bb {
  strings:
    $key_a2bb = { f1 d4 [2] d5 da [2] fe f6 [2] d0 d4 [2] c4 cf [2] cb d5 [2] d5 c8 [2] d7 c9 [2] cc cf [2] d0 c8 [2] cc e7 }

  condition:
    any of them
}