rule TTP_XOR_QUAD_CurrentVersionRun_a2ad {
  strings:
    $key_a2ad = { f1 c2 [2] d5 cc [2] fe e0 [2] d0 c2 [2] c4 d9 [2] cb c3 [2] d5 de [2] d7 df [2] cc d9 [2] d0 de [2] cc f1 }

  condition:
    any of them
}