rule TTP_XOR_QUAD_CurrentVersionRun_cd69 {
  strings:
    $key_cd69 = { 9e 06 [2] ba 08 [2] 91 24 [2] bf 06 [2] ab 1d [2] a4 07 [2] ba 1a [2] b8 1b [2] a3 1d [2] bf 1a [2] a3 35 }

  condition:
    any of them
}