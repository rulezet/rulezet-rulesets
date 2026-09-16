rule TTP_XOR_QUAD_CurrentVersionRun_cdb7 {
  strings:
    $key_cdb7 = { 9e d8 [2] ba d6 [2] 91 fa [2] bf d8 [2] ab c3 [2] a4 d9 [2] ba c4 [2] b8 c5 [2] a3 c3 [2] bf c4 [2] a3 eb }

  condition:
    any of them
}