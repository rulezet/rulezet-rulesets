rule TTP_XOR_QUAD_CurrentVersionRun_a2cc {
  strings:
    $key_a2cc = { f1 a3 [2] d5 ad [2] fe 81 [2] d0 a3 [2] c4 b8 [2] cb a2 [2] d5 bf [2] d7 be [2] cc b8 [2] d0 bf [2] cc 90 }

  condition:
    any of them
}