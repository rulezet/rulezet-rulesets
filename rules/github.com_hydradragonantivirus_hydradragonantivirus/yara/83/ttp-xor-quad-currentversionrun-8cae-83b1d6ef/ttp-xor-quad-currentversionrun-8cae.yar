rule TTP_XOR_QUAD_CurrentVersionRun_8cae {
  strings:
    $key_8cae = { df c1 [2] fb cf [2] d0 e3 [2] fe c1 [2] ea da [2] e5 c0 [2] fb dd [2] f9 dc [2] e2 da [2] fe dd [2] e2 f2 }

  condition:
    any of them
}