rule TTP_XOR_QUAD_CurrentVersionRun_cd18 {
  strings:
    $key_cd18 = { 9e 77 [2] ba 79 [2] 91 55 [2] bf 77 [2] ab 6c [2] a4 76 [2] ba 6b [2] b8 6a [2] a3 6c [2] bf 6b [2] a3 44 }

  condition:
    any of them
}