rule TTP_XOR_QUAD_CurrentVersionRun_b790 {
  strings:
    $key_b790 = { e4 ff [2] c0 f1 [2] eb dd [2] c5 ff [2] d1 e4 [2] de fe [2] c0 e3 [2] c2 e2 [2] d9 e4 [2] c5 e3 [2] d9 cc }

  condition:
    any of them
}