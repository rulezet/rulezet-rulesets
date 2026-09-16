rule TTP_XOR_MULT_DOSStub_5686 {
  strings:
    $key_5686 = { 02 ee [2] 76 f6 [2] 31 f4 [2] 76 e5 [2] 38 e9 [2] 34 e3 [2] 23 e8 [2] 38 a6 [2] 05 }

  condition:
    any of them
}