rule TTP_XOR_QUAD_CurrentVersionRun_0dbc {
  strings:
    $key_0dbc = { 5e d3 [2] 7a dd [2] 51 f1 [2] 7f d3 [2] 6b c8 [2] 64 d2 [2] 7a cf [2] 78 ce [2] 63 c8 [2] 7f cf [2] 63 e0 }

  condition:
    any of them
}