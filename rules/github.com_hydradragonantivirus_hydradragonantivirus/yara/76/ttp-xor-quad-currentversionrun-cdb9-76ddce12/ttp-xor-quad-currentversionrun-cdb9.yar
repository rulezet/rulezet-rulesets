rule TTP_XOR_QUAD_CurrentVersionRun_cdb9 {
  strings:
    $key_cdb9 = { 9e d6 [2] ba d8 [2] 91 f4 [2] bf d6 [2] ab cd [2] a4 d7 [2] ba ca [2] b8 cb [2] a3 cd [2] bf ca [2] a3 e5 }

  condition:
    any of them
}