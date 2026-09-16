rule TTP_XOR_QUAD_CurrentVersionRun_cdaa {
  strings:
    $key_cdaa = { 9e c5 [2] ba cb [2] 91 e7 [2] bf c5 [2] ab de [2] a4 c4 [2] ba d9 [2] b8 d8 [2] a3 de [2] bf d9 [2] a3 f6 }

  condition:
    any of them
}