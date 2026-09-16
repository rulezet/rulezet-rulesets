rule TTP_XOR_QUAD_CurrentVersionRun_2e90 {
  strings:
    $key_2e90 = { 7d ff [2] 59 f1 [2] 72 dd [2] 5c ff [2] 48 e4 [2] 47 fe [2] 59 e3 [2] 5b e2 [2] 40 e4 [2] 5c e3 [2] 40 cc }

  condition:
    any of them
}