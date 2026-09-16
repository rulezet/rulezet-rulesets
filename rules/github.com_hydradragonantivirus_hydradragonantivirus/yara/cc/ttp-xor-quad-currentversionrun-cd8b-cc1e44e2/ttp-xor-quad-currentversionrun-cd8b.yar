rule TTP_XOR_QUAD_CurrentVersionRun_cd8b {
  strings:
    $key_cd8b = { 9e e4 [2] ba ea [2] 91 c6 [2] bf e4 [2] ab ff [2] a4 e5 [2] ba f8 [2] b8 f9 [2] a3 ff [2] bf f8 [2] a3 d7 }

  condition:
    any of them
}