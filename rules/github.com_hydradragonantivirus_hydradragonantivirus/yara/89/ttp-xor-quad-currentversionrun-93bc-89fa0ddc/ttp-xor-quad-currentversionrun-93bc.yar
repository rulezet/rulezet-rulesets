rule TTP_XOR_QUAD_CurrentVersionRun_93bc {
  strings:
    $key_93bc = { c0 d3 [2] e4 dd [2] cf f1 [2] e1 d3 [2] f5 c8 [2] fa d2 [2] e4 cf [2] e6 ce [2] fd c8 [2] e1 cf [2] fd e0 }

  condition:
    any of them
}