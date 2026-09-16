rule TTP_XOR_QUAD_CurrentVersionRun_0990 {
  strings:
    $key_0990 = { 5a ff [2] 7e f1 [2] 55 dd [2] 7b ff [2] 6f e4 [2] 60 fe [2] 7e e3 [2] 7c e2 [2] 67 e4 [2] 7b e3 [2] 67 cc }

  condition:
    any of them
}