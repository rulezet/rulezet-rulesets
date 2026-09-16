rule TTP_XOR_QUAD_CurrentVersionRun_5b90 {
  strings:
    $key_5b90 = { 08 ff [2] 2c f1 [2] 07 dd [2] 29 ff [2] 3d e4 [2] 32 fe [2] 2c e3 [2] 2e e2 [2] 35 e4 [2] 29 e3 [2] 35 cc }

  condition:
    any of them
}