rule TTP_XOR_QUAD_CurrentVersionRun_cd40 {
  strings:
    $key_cd40 = { 9e 2f [2] ba 21 [2] 91 0d [2] bf 2f [2] ab 34 [2] a4 2e [2] ba 33 [2] b8 32 [2] a3 34 [2] bf 33 [2] a3 1c }

  condition:
    any of them
}