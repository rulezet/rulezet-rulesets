rule TTP_XOR_QUAD_CurrentVersionRun_bcbc {
  strings:
    $key_bcbc = { ef d3 [2] cb dd [2] e0 f1 [2] ce d3 [2] da c8 [2] d5 d2 [2] cb cf [2] c9 ce [2] d2 c8 [2] ce cf [2] d2 e0 }

  condition:
    any of them
}