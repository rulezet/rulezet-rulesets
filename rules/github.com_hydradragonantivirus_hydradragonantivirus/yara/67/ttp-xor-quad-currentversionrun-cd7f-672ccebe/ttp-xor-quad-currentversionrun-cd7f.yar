rule TTP_XOR_QUAD_CurrentVersionRun_cd7f {
  strings:
    $key_cd7f = { 9e 10 [2] ba 1e [2] 91 32 [2] bf 10 [2] ab 0b [2] a4 11 [2] ba 0c [2] b8 0d [2] a3 0b [2] bf 0c [2] a3 23 }

  condition:
    any of them
}