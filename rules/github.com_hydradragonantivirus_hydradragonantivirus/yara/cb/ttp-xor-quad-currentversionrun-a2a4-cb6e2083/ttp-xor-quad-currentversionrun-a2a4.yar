rule TTP_XOR_QUAD_CurrentVersionRun_a2a4 {
  strings:
    $key_a2a4 = { f1 cb [2] d5 c5 [2] fe e9 [2] d0 cb [2] c4 d0 [2] cb ca [2] d5 d7 [2] d7 d6 [2] cc d0 [2] d0 d7 [2] cc f8 }

  condition:
    any of them
}