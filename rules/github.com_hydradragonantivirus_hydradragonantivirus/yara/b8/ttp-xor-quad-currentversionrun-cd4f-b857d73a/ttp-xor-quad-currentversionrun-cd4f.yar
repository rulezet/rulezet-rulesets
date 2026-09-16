rule TTP_XOR_QUAD_CurrentVersionRun_cd4f {
  strings:
    $key_cd4f = { 9e 20 [2] ba 2e [2] 91 02 [2] bf 20 [2] ab 3b [2] a4 21 [2] ba 3c [2] b8 3d [2] a3 3b [2] bf 3c [2] a3 13 }

  condition:
    any of them
}