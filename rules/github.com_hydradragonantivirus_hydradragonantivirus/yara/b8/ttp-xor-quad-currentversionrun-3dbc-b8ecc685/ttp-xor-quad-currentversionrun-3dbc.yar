rule TTP_XOR_QUAD_CurrentVersionRun_3dbc {
  strings:
    $key_3dbc = { 6e d3 [2] 4a dd [2] 61 f1 [2] 4f d3 [2] 5b c8 [2] 54 d2 [2] 4a cf [2] 48 ce [2] 53 c8 [2] 4f cf [2] 53 e0 }

  condition:
    any of them
}