rule TTP_XOR_QUAD_CurrentVersionRun_c890 {
  strings:
    $key_c890 = { 9b ff [2] bf f1 [2] 94 dd [2] ba ff [2] ae e4 [2] a1 fe [2] bf e3 [2] bd e2 [2] a6 e4 [2] ba e3 [2] a6 cc }

  condition:
    any of them
}