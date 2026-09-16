rule TTP_XOR_QUAD_CurrentVersionRun_2a90 {
  strings:
    $key_2a90 = { 79 ff [2] 5d f1 [2] 76 dd [2] 58 ff [2] 4c e4 [2] 43 fe [2] 5d e3 [2] 5f e2 [2] 44 e4 [2] 58 e3 [2] 44 cc }

  condition:
    any of them
}