rule TTP_XOR_QUAD_CurrentVersionRun_1990 {
  strings:
    $key_1990 = { 4a ff [2] 6e f1 [2] 45 dd [2] 6b ff [2] 7f e4 [2] 70 fe [2] 6e e3 [2] 6c e2 [2] 77 e4 [2] 6b e3 [2] 77 cc }

  condition:
    any of them
}