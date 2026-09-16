rule TTP_XOR_QUAD_CurrentVersionRun_cd1c {
  strings:
    $key_cd1c = { 9e 73 [2] ba 7d [2] 91 51 [2] bf 73 [2] ab 68 [2] a4 72 [2] ba 6f [2] b8 6e [2] a3 68 [2] bf 6f [2] a3 40 }

  condition:
    any of them
}