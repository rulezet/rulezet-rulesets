rule TTP_XOR_MULT_DOSStub_65b4 {
  strings:
    $key_65b4 = { 31 dc [2] 45 c4 [2] 02 c6 [2] 45 d7 [2] 0b db [2] 07 d1 [2] 10 da [2] 0b 94 [2] 36 }

  condition:
    any of them
}