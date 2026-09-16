rule TTP_XOR_MULT_DOSStub_f0b9 {
  strings:
    $key_f0b9 = { a4 d1 [2] d0 c9 [2] 97 cb [2] d0 da [2] 9e d6 [2] 92 dc [2] 85 d7 [2] 9e 99 [2] a3 }

  condition:
    any of them
}