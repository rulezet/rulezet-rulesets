rule TTP_XOR_QUAD_CurrentVersionRun_a2aa {
  strings:
    $key_a2aa = { f1 c5 [2] d5 cb [2] fe e7 [2] d0 c5 [2] c4 de [2] cb c4 [2] d5 d9 [2] d7 d8 [2] cc de [2] d0 d9 [2] cc f6 }

  condition:
    any of them
}