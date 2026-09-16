rule TTP_XOR_QUAD_CurrentVersionRun_cd7d {
  strings:
    $key_cd7d = { 9e 12 [2] ba 1c [2] 91 30 [2] bf 12 [2] ab 09 [2] a4 13 [2] ba 0e [2] b8 0f [2] a3 09 [2] bf 0e [2] a3 21 }

  condition:
    any of them
}