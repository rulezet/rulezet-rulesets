rule TTP_XOR_QUAD_CurrentVersionRun_bcba {
  strings:
    $key_bcba = { ef d5 [2] cb db [2] e0 f7 [2] ce d5 [2] da ce [2] d5 d4 [2] cb c9 [2] c9 c8 [2] d2 ce [2] ce c9 [2] d2 e6 }

  condition:
    any of them
}