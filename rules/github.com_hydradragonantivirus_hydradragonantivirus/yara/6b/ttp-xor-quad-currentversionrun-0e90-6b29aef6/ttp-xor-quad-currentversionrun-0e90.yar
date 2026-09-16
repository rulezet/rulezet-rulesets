rule TTP_XOR_QUAD_CurrentVersionRun_0e90 {
  strings:
    $key_0e90 = { 5d ff [2] 79 f1 [2] 52 dd [2] 7c ff [2] 68 e4 [2] 67 fe [2] 79 e3 [2] 7b e2 [2] 60 e4 [2] 7c e3 [2] 60 cc }

  condition:
    any of them
}