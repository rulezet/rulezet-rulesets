rule TTP_XOR_QUAD_CurrentVersionRun_7990 {
  strings:
    $key_7990 = { 2a ff [2] 0e f1 [2] 25 dd [2] 0b ff [2] 1f e4 [2] 10 fe [2] 0e e3 [2] 0c e2 [2] 17 e4 [2] 0b e3 [2] 17 cc }

  condition:
    any of them
}