rule TTP_XOR_QUAD_CurrentVersionRun_5e90 {
  strings:
    $key_5e90 = { 0d ff [2] 29 f1 [2] 02 dd [2] 2c ff [2] 38 e4 [2] 37 fe [2] 29 e3 [2] 2b e2 [2] 30 e4 [2] 2c e3 [2] 30 cc }

  condition:
    any of them
}