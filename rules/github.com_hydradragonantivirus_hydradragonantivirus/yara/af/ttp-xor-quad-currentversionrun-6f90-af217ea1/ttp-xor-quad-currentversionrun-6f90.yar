rule TTP_XOR_QUAD_CurrentVersionRun_6f90 {
  strings:
    $key_6f90 = { 3c ff [2] 18 f1 [2] 33 dd [2] 1d ff [2] 09 e4 [2] 06 fe [2] 18 e3 [2] 1a e2 [2] 01 e4 [2] 1d e3 [2] 01 cc }

  condition:
    any of them
}