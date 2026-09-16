rule TTP_XOR_MULT_DOSStub_fdb1 {
  strings:
    $key_fdb1 = { a9 d9 [2] dd c1 [2] 9a c3 [2] dd d2 [2] 93 de [2] 9f d4 [2] 88 df [2] 93 91 [2] ae }

  condition:
    any of them
}