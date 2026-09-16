rule TTP_XOR_QUAD_CurrentVersionRun_97ae {
  strings:
    $key_97ae = { c4 c1 [2] e0 cf [2] cb e3 [2] e5 c1 [2] f1 da [2] fe c0 [2] e0 dd [2] e2 dc [2] f9 da [2] e5 dd [2] f9 f2 }

  condition:
    any of them
}