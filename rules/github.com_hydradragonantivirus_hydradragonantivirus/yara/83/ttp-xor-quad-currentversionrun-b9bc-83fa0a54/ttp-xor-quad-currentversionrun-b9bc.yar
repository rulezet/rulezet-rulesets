rule TTP_XOR_QUAD_CurrentVersionRun_b9bc {
  strings:
    $key_b9bc = { ea d3 [2] ce dd [2] e5 f1 [2] cb d3 [2] df c8 [2] d0 d2 [2] ce cf [2] cc ce [2] d7 c8 [2] cb cf [2] d7 e0 }

  condition:
    any of them
}