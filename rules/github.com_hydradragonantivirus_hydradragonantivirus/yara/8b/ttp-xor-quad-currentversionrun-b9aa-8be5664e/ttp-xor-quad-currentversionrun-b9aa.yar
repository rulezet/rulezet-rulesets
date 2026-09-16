rule TTP_XOR_QUAD_CurrentVersionRun_b9aa {
  strings:
    $key_b9aa = { ea c5 [2] ce cb [2] e5 e7 [2] cb c5 [2] df de [2] d0 c4 [2] ce d9 [2] cc d8 [2] d7 de [2] cb d9 [2] d7 f6 }

  condition:
    any of them
}