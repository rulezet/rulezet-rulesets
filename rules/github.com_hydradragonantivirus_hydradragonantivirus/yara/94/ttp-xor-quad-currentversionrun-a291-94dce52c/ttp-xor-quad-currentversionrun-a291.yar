rule TTP_XOR_QUAD_CurrentVersionRun_a291 {
  strings:
    $key_a291 = { f1 fe [2] d5 f0 [2] fe dc [2] d0 fe [2] c4 e5 [2] cb ff [2] d5 e2 [2] d7 e3 [2] cc e5 [2] d0 e2 [2] cc cd }

  condition:
    any of them
}