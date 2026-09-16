rule TTP_XOR_QUAD_CurrentVersionRun_a2a2 {
  strings:
    $key_a2a2 = { f1 cd [2] d5 c3 [2] fe ef [2] d0 cd [2] c4 d6 [2] cb cc [2] d5 d1 [2] d7 d0 [2] cc d6 [2] d0 d1 [2] cc fe }

  condition:
    any of them
}