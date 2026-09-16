rule TTP_XOR_QUAD_CurrentVersionRun_94bc {
  strings:
    $key_94bc = { c7 d3 [2] e3 dd [2] c8 f1 [2] e6 d3 [2] f2 c8 [2] fd d2 [2] e3 cf [2] e1 ce [2] fa c8 [2] e6 cf [2] fa e0 }

  condition:
    any of them
}