rule TTP_XOR_QUAD_CurrentVersionRun_a2c0 {
  strings:
    $key_a2c0 = { f1 af [2] d5 a1 [2] fe 8d [2] d0 af [2] c4 b4 [2] cb ae [2] d5 b3 [2] d7 b2 [2] cc b4 [2] d0 b3 [2] cc 9c }

  condition:
    any of them
}