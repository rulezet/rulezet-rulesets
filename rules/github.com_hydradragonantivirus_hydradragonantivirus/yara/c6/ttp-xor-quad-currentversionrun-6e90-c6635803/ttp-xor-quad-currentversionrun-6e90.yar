rule TTP_XOR_QUAD_CurrentVersionRun_6e90 {
  strings:
    $key_6e90 = { 3d ff [2] 19 f1 [2] 32 dd [2] 1c ff [2] 08 e4 [2] 07 fe [2] 19 e3 [2] 1b e2 [2] 00 e4 [2] 1c e3 [2] 00 cc }

  condition:
    any of them
}