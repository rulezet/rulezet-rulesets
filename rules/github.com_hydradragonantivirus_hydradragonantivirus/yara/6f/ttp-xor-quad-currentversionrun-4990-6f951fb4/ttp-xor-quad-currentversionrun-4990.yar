rule TTP_XOR_QUAD_CurrentVersionRun_4990 {
  strings:
    $key_4990 = { 1a ff [2] 3e f1 [2] 15 dd [2] 3b ff [2] 2f e4 [2] 20 fe [2] 3e e3 [2] 3c e2 [2] 27 e4 [2] 3b e3 [2] 27 cc }

  condition:
    any of them
}