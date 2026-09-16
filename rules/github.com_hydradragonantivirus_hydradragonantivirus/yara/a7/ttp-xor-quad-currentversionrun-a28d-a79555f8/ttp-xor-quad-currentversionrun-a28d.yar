rule TTP_XOR_QUAD_CurrentVersionRun_a28d {
  strings:
    $key_a28d = { f1 e2 [2] d5 ec [2] fe c0 [2] d0 e2 [2] c4 f9 [2] cb e3 [2] d5 fe [2] d7 ff [2] cc f9 [2] d0 fe [2] cc d1 }

  condition:
    any of them
}