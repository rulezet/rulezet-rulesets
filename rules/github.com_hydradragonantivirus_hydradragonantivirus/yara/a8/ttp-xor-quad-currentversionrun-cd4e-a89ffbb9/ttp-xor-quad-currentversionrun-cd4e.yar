rule TTP_XOR_QUAD_CurrentVersionRun_cd4e {
  strings:
    $key_cd4e = { 9e 21 [2] ba 2f [2] 91 03 [2] bf 21 [2] ab 3a [2] a4 20 [2] ba 3d [2] b8 3c [2] a3 3a [2] bf 3d [2] a3 12 }

  condition:
    any of them
}