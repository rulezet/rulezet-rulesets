rule TTP_XOR_QUAD_CurrentVersionRun_3f90 {
  strings:
    $key_3f90 = { 6c ff [2] 48 f1 [2] 63 dd [2] 4d ff [2] 59 e4 [2] 56 fe [2] 48 e3 [2] 4a e2 [2] 51 e4 [2] 4d e3 [2] 51 cc }

  condition:
    any of them
}