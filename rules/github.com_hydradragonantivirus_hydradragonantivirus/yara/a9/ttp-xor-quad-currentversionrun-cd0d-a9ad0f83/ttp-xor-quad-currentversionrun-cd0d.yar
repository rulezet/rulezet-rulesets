rule TTP_XOR_QUAD_CurrentVersionRun_cd0d {
  strings:
    $key_cd0d = { 9e 62 [2] ba 6c [2] 91 40 [2] bf 62 [2] ab 79 [2] a4 63 [2] ba 7e [2] b8 7f [2] a3 79 [2] bf 7e [2] a3 51 }

  condition:
    any of them
}