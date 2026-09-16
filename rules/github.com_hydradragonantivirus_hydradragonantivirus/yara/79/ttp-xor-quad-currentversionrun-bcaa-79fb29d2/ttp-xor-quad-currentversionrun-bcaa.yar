rule TTP_XOR_QUAD_CurrentVersionRun_bcaa {
  strings:
    $key_bcaa = { ef c5 [2] cb cb [2] e0 e7 [2] ce c5 [2] da de [2] d5 c4 [2] cb d9 [2] c9 d8 [2] d2 de [2] ce d9 [2] d2 f6 }

  condition:
    any of them
}