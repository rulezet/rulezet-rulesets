rule TTP_XOR_QUAD_CurrentVersionRun_1a90 {
  strings:
    $key_1a90 = { 49 ff [2] 6d f1 [2] 46 dd [2] 68 ff [2] 7c e4 [2] 73 fe [2] 6d e3 [2] 6f e2 [2] 74 e4 [2] 68 e3 [2] 74 cc }

  condition:
    any of them
}