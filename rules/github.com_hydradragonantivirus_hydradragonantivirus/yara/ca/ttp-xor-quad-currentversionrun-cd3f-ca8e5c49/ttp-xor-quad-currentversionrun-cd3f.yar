rule TTP_XOR_QUAD_CurrentVersionRun_cd3f {
  strings:
    $key_cd3f = { 9e 50 [2] ba 5e [2] 91 72 [2] bf 50 [2] ab 4b [2] a4 51 [2] ba 4c [2] b8 4d [2] a3 4b [2] bf 4c [2] a3 63 }

  condition:
    any of them
}