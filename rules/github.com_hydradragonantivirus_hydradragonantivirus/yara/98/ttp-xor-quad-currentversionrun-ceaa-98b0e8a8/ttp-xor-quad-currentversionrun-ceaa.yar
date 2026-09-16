rule TTP_XOR_QUAD_CurrentVersionRun_ceaa {
  strings:
    $key_ceaa = { 9d c5 [2] b9 cb [2] 92 e7 [2] bc c5 [2] a8 de [2] a7 c4 [2] b9 d9 [2] bb d8 [2] a0 de [2] bc d9 [2] a0 f6 }

  condition:
    any of them
}