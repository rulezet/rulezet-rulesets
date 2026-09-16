rule TTP_XOR_QUAD_CurrentVersionRun_e790 {
  strings:
    $key_e790 = { b4 ff [2] 90 f1 [2] bb dd [2] 95 ff [2] 81 e4 [2] 8e fe [2] 90 e3 [2] 92 e2 [2] 89 e4 [2] 95 e3 [2] 89 cc }

  condition:
    any of them
}