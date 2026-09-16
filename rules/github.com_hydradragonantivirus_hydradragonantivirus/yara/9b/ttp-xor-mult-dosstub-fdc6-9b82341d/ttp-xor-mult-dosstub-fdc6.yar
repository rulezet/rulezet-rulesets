rule TTP_XOR_MULT_DOSStub_fdc6 {
  strings:
    $key_fdc6 = { a9 ae [2] dd b6 [2] 9a b4 [2] dd a5 [2] 93 a9 [2] 9f a3 [2] 88 a8 [2] 93 e6 [2] ae }

  condition:
    any of them
}