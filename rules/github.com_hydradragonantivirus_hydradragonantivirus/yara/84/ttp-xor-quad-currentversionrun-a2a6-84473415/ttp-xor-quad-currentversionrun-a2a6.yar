rule TTP_XOR_QUAD_CurrentVersionRun_a2a6 {
  strings:
    $key_a2a6 = { f1 c9 [2] d5 c7 [2] fe eb [2] d0 c9 [2] c4 d2 [2] cb c8 [2] d5 d5 [2] d7 d4 [2] cc d2 [2] d0 d5 [2] cc fa }

  condition:
    any of them
}