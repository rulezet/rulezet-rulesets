rule TTP_XOR_QUAD_CurrentVersionRun_6890 {
  strings:
    $key_6890 = { 3b ff [2] 1f f1 [2] 34 dd [2] 1a ff [2] 0e e4 [2] 01 fe [2] 1f e3 [2] 1d e2 [2] 06 e4 [2] 1a e3 [2] 06 cc }

  condition:
    any of them
}