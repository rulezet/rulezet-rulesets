rule TTP_XOR_QUAD_CurrentVersionRun_a5ae {
  strings:
    $key_a5ae = { f6 c1 [2] d2 cf [2] f9 e3 [2] d7 c1 [2] c3 da [2] cc c0 [2] d2 dd [2] d0 dc [2] cb da [2] d7 dd [2] cb f2 }

  condition:
    any of them
}