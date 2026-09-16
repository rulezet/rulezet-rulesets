rule TTP_XOR_QUAD_CurrentVersionRun_7e90 {
  strings:
    $key_7e90 = { 2d ff [2] 09 f1 [2] 22 dd [2] 0c ff [2] 18 e4 [2] 17 fe [2] 09 e3 [2] 0b e2 [2] 10 e4 [2] 0c e3 [2] 10 cc }

  condition:
    any of them
}