rule TTP_XOR_QUAD_CurrentVersionRun_cd90 {
  strings:
    $key_cd90 = { 9e ff [2] ba f1 [2] 91 dd [2] bf ff [2] ab e4 [2] a4 fe [2] ba e3 [2] b8 e2 [2] a3 e4 [2] bf e3 [2] a3 cc }

  condition:
    any of them
}