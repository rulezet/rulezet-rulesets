rule TTP_XOR_QUAD_CurrentVersionRun_e990 {
  strings:
    $key_e990 = { ba ff [2] 9e f1 [2] b5 dd [2] 9b ff [2] 8f e4 [2] 80 fe [2] 9e e3 [2] 9c e2 [2] 87 e4 [2] 9b e3 [2] 87 cc }

  condition:
    any of them
}