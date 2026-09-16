rule TTP_XOR_QUAD_CurrentVersionRun_cd20 {
  strings:
    $key_cd20 = { 9e 4f [2] ba 41 [2] 91 6d [2] bf 4f [2] ab 54 [2] a4 4e [2] ba 53 [2] b8 52 [2] a3 54 [2] bf 53 [2] a3 7c }

  condition:
    any of them
}