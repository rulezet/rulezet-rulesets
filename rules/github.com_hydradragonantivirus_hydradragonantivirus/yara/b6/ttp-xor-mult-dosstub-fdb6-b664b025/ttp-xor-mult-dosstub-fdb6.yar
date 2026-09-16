rule TTP_XOR_MULT_DOSStub_fdb6 {
  strings:
    $key_fdb6 = { a9 de [2] dd c6 [2] 9a c4 [2] dd d5 [2] 93 d9 [2] 9f d3 [2] 88 d8 [2] 93 96 [2] ae }

  condition:
    any of them
}