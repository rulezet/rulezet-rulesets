rule TTP_XOR_MULT_DOSStub_6586 {
  strings:
    $key_6586 = { 31 ee [2] 45 f6 [2] 02 f4 [2] 45 e5 [2] 0b e9 [2] 07 e3 [2] 10 e8 [2] 0b a6 [2] 36 }

  condition:
    any of them
}