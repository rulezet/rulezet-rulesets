rule TTP_XOR_QUAD_CurrentVersionRun_1e90 {
  strings:
    $key_1e90 = { 4d ff [2] 69 f1 [2] 42 dd [2] 6c ff [2] 78 e4 [2] 77 fe [2] 69 e3 [2] 6b e2 [2] 70 e4 [2] 6c e3 [2] 70 cc }

  condition:
    any of them
}