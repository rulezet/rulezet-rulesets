rule TTP_XOR_QUAD_CurrentVersionRun_cd68 {
  strings:
    $key_cd68 = { 9e 07 [2] ba 09 [2] 91 25 [2] bf 07 [2] ab 1c [2] a4 06 [2] ba 1b [2] b8 1a [2] a3 1c [2] bf 1b [2] a3 34 }

  condition:
    any of them
}