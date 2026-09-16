rule TTP_XOR_QUAD_CurrentVersionRun_bcbb {
  strings:
    $key_bcbb = { ef d4 [2] cb da [2] e0 f6 [2] ce d4 [2] da cf [2] d5 d5 [2] cb c8 [2] c9 c9 [2] d2 cf [2] ce c8 [2] d2 e7 }

  condition:
    any of them
}