rule TTP_XOR_QUAD_CurrentVersionRun_beaa {
  strings:
    $key_beaa = { ed c5 [2] c9 cb [2] e2 e7 [2] cc c5 [2] d8 de [2] d7 c4 [2] c9 d9 [2] cb d8 [2] d0 de [2] cc d9 [2] d0 f6 }

  condition:
    any of them
}