rule TTP_XOR_QUAD_CurrentVersionRun_5dbc {
  strings:
    $key_5dbc = { 0e d3 [2] 2a dd [2] 01 f1 [2] 2f d3 [2] 3b c8 [2] 34 d2 [2] 2a cf [2] 28 ce [2] 33 c8 [2] 2f cf [2] 33 e0 }

  condition:
    any of them
}