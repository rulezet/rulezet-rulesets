rule TTP_XOR_QUAD_CurrentVersionRun_7dbc {
  strings:
    $key_7dbc = { 2e d3 [2] 0a dd [2] 21 f1 [2] 0f d3 [2] 1b c8 [2] 14 d2 [2] 0a cf [2] 08 ce [2] 13 c8 [2] 0f cf [2] 13 e0 }

  condition:
    any of them
}