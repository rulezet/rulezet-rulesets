rule TTP_XOR_QUAD_CurrentVersionRun_cd5d {
  strings:
    $key_cd5d = { 9e 32 [2] ba 3c [2] 91 10 [2] bf 32 [2] ab 29 [2] a4 33 [2] ba 2e [2] b8 2f [2] a3 29 [2] bf 2e [2] a3 01 }

  condition:
    any of them
}