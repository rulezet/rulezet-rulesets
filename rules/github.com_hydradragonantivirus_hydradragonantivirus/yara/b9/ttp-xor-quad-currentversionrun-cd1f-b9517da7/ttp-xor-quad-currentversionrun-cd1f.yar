rule TTP_XOR_QUAD_CurrentVersionRun_cd1f {
  strings:
    $key_cd1f = { 9e 70 [2] ba 7e [2] 91 52 [2] bf 70 [2] ab 6b [2] a4 71 [2] ba 6c [2] b8 6d [2] a3 6b [2] bf 6c [2] a3 43 }

  condition:
    any of them
}