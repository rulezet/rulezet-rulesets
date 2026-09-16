rule TTP_XOR_QUAD_CurrentVersionRun_1f90 {
  strings:
    $key_1f90 = { 4c ff [2] 68 f1 [2] 43 dd [2] 6d ff [2] 79 e4 [2] 76 fe [2] 68 e3 [2] 6a e2 [2] 71 e4 [2] 6d e3 [2] 71 cc }

  condition:
    any of them
}