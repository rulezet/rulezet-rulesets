rule TTP_XOR_MULT_DOSStub_0786 {
  strings:
    $key_0786 = { 53 ee [2] 27 f6 [2] 60 f4 [2] 27 e5 [2] 69 e9 [2] 65 e3 [2] 72 e8 [2] 69 a6 [2] 54 }

  condition:
    any of them
}