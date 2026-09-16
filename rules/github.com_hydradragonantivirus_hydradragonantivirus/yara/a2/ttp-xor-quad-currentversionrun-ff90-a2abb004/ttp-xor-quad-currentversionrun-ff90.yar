rule TTP_XOR_QUAD_CurrentVersionRun_ff90 {
  strings:
    $key_ff90 = { ac ff [2] 88 f1 [2] a3 dd [2] 8d ff [2] 99 e4 [2] 96 fe [2] 88 e3 [2] 8a e2 [2] 91 e4 [2] 8d e3 [2] 91 cc }

  condition:
    any of them
}