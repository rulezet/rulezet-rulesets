rule TTP_XOR_QUAD_CurrentVersionRun_a293 {
  strings:
    $key_a293 = { f1 fc [2] d5 f2 [2] fe de [2] d0 fc [2] c4 e7 [2] cb fd [2] d5 e0 [2] d7 e1 [2] cc e7 [2] d0 e0 [2] cc cf }

  condition:
    any of them
}