rule TTP_XOR_QUAD_CurrentVersionRun_a590 {
  strings:
    $key_a590 = { f6 ff [2] d2 f1 [2] f9 dd [2] d7 ff [2] c3 e4 [2] cc fe [2] d2 e3 [2] d0 e2 [2] cb e4 [2] d7 e3 [2] cb cc }

  condition:
    any of them
}