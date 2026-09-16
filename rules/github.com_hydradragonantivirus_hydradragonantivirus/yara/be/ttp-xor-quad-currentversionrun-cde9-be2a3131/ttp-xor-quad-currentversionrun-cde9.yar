rule TTP_XOR_QUAD_CurrentVersionRun_cde9 {
  strings:
    $key_cde9 = { 9e 86 [2] ba 88 [2] 91 a4 [2] bf 86 [2] ab 9d [2] a4 87 [2] ba 9a [2] b8 9b [2] a3 9d [2] bf 9a [2] a3 b5 }

  condition:
    any of them
}