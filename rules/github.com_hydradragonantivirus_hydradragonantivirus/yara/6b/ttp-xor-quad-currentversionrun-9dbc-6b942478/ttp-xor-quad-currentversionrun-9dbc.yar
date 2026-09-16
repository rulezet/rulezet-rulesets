rule TTP_XOR_QUAD_CurrentVersionRun_9dbc {
  strings:
    $key_9dbc = { ce d3 [2] ea dd [2] c1 f1 [2] ef d3 [2] fb c8 [2] f4 d2 [2] ea cf [2] e8 ce [2] f3 c8 [2] ef cf [2] f3 e0 }

  condition:
    any of them
}