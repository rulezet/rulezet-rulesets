rule TTP_XOR_QUAD_CurrentVersionRun_e390 {
  strings:
    $key_e390 = { b0 ff [2] 94 f1 [2] bf dd [2] 91 ff [2] 85 e4 [2] 8a fe [2] 94 e3 [2] 96 e2 [2] 8d e4 [2] 91 e3 [2] 8d cc }

  condition:
    any of them
}