rule TTP_XOR_QUAD_CurrentVersionRun_b9bd {
  strings:
    $key_b9bd = { ea d2 [2] ce dc [2] e5 f0 [2] cb d2 [2] df c9 [2] d0 d3 [2] ce ce [2] cc cf [2] d7 c9 [2] cb ce [2] d7 e1 }

  condition:
    any of them
}