rule TTP_XOR_QUAD_CurrentVersionRun_f590 {
  strings:
    $key_f590 = { a6 ff [2] 82 f1 [2] a9 dd [2] 87 ff [2] 93 e4 [2] 9c fe [2] 82 e3 [2] 80 e2 [2] 9b e4 [2] 87 e3 [2] 9b cc }

  condition:
    any of them
}