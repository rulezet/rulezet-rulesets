rule TTP_XOR_QUAD_CurrentVersionRun_0790 {
  strings:
    $key_0790 = { 54 ff [2] 70 f1 [2] 5b dd [2] 75 ff [2] 61 e4 [2] 6e fe [2] 70 e3 [2] 72 e2 [2] 69 e4 [2] 75 e3 [2] 69 cc }

  condition:
    any of them
}