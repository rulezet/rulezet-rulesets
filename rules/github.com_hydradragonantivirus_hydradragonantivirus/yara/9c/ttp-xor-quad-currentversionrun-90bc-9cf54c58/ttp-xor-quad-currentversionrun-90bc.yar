rule TTP_XOR_QUAD_CurrentVersionRun_90bc {
  strings:
    $key_90bc = { c3 d3 [2] e7 dd [2] cc f1 [2] e2 d3 [2] f6 c8 [2] f9 d2 [2] e7 cf [2] e5 ce [2] fe c8 [2] e2 cf [2] fe e0 }

  condition:
    any of them
}