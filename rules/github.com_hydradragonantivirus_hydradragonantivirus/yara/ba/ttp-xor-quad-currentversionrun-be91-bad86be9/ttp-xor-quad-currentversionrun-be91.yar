rule TTP_XOR_QUAD_CurrentVersionRun_be91 {
  strings:
    $key_be91 = { ed fe [2] c9 f0 [2] e2 dc [2] cc fe [2] d8 e5 [2] d7 ff [2] c9 e2 [2] cb e3 [2] d0 e5 [2] cc e2 [2] d0 cd }

  condition:
    any of them
}