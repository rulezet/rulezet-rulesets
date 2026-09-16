rule TTP_XOR_QUAD_CurrentVersionRun_7b90 {
  strings:
    $key_7b90 = { 28 ff [2] 0c f1 [2] 27 dd [2] 09 ff [2] 1d e4 [2] 12 fe [2] 0c e3 [2] 0e e2 [2] 15 e4 [2] 09 e3 [2] 15 cc }

  condition:
    any of them
}