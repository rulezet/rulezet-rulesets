rule TTP_XOR_QUAD_CurrentVersionRun_90bb {
  strings:
    $key_90bb = { c3 d4 [2] e7 da [2] cc f6 [2] e2 d4 [2] f6 cf [2] f9 d5 [2] e7 c8 [2] e5 c9 [2] fe cf [2] e2 c8 [2] fe e7 }

  condition:
    any of them
}