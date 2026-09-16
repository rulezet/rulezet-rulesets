rule TTP_XOR_QUAD_CurrentVersionRun_7f90 {
  strings:
    $key_7f90 = { 2c ff [2] 08 f1 [2] 23 dd [2] 0d ff [2] 19 e4 [2] 16 fe [2] 08 e3 [2] 0a e2 [2] 11 e4 [2] 0d e3 [2] 11 cc }

  condition:
    any of them
}