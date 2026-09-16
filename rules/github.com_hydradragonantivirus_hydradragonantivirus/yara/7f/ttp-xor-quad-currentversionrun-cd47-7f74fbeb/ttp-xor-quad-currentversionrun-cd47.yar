rule TTP_XOR_QUAD_CurrentVersionRun_cd47 {
  strings:
    $key_cd47 = { 9e 28 [2] ba 26 [2] 91 0a [2] bf 28 [2] ab 33 [2] a4 29 [2] ba 34 [2] b8 35 [2] a3 33 [2] bf 34 [2] a3 1b }

  condition:
    any of them
}