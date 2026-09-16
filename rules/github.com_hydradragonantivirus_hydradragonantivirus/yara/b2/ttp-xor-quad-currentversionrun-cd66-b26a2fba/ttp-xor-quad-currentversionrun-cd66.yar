rule TTP_XOR_QUAD_CurrentVersionRun_cd66 {
  strings:
    $key_cd66 = { 9e 09 [2] ba 07 [2] 91 2b [2] bf 09 [2] ab 12 [2] a4 08 [2] ba 15 [2] b8 14 [2] a3 12 [2] bf 15 [2] a3 3a }

  condition:
    any of them
}