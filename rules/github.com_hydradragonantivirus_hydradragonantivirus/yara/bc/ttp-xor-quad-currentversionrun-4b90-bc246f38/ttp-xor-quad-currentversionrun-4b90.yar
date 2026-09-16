rule TTP_XOR_QUAD_CurrentVersionRun_4b90 {
  strings:
    $key_4b90 = { 18 ff [2] 3c f1 [2] 17 dd [2] 39 ff [2] 2d e4 [2] 22 fe [2] 3c e3 [2] 3e e2 [2] 25 e4 [2] 39 e3 [2] 25 cc }

  condition:
    any of them
}