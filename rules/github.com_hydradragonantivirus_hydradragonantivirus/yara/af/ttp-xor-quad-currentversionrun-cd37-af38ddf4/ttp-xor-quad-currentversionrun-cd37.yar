rule TTP_XOR_QUAD_CurrentVersionRun_cd37 {
  strings:
    $key_cd37 = { 9e 58 [2] ba 56 [2] 91 7a [2] bf 58 [2] ab 43 [2] a4 59 [2] ba 44 [2] b8 45 [2] a3 43 [2] bf 44 [2] a3 6b }

  condition:
    any of them
}