rule TTP_XOR_QUAD_CurrentVersionRun_cd3d {
  strings:
    $key_cd3d = { 9e 52 [2] ba 5c [2] 91 70 [2] bf 52 [2] ab 49 [2] a4 53 [2] ba 4e [2] b8 4f [2] a3 49 [2] bf 4e [2] a3 61 }

  condition:
    any of them
}