rule TTP_XOR_QUAD_CurrentVersionRun_bcb7 {
  strings:
    $key_bcb7 = { ef d8 [2] cb d6 [2] e0 fa [2] ce d8 [2] da c3 [2] d5 d9 [2] cb c4 [2] c9 c5 [2] d2 c3 [2] ce c4 [2] d2 eb }

  condition:
    any of them
}