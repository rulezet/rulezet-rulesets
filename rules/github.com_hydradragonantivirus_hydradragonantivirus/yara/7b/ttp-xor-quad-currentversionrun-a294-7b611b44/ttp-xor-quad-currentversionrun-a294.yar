rule TTP_XOR_QUAD_CurrentVersionRun_a294 {
  strings:
    $key_a294 = { f1 fb [2] d5 f5 [2] fe d9 [2] d0 fb [2] c4 e0 [2] cb fa [2] d5 e7 [2] d7 e6 [2] cc e0 [2] d0 e7 [2] cc c8 }

  condition:
    any of them
}