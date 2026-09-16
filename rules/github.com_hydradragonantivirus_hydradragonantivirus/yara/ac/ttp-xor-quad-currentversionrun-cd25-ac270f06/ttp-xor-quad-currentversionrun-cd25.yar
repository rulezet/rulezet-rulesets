rule TTP_XOR_QUAD_CurrentVersionRun_cd25 {
  strings:
    $key_cd25 = { 9e 4a [2] ba 44 [2] 91 68 [2] bf 4a [2] ab 51 [2] a4 4b [2] ba 56 [2] b8 57 [2] a3 51 [2] bf 56 [2] a3 79 }

  condition:
    any of them
}