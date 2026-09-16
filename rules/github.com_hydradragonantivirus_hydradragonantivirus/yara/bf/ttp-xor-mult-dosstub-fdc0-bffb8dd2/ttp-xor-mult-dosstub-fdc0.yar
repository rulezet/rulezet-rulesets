rule TTP_XOR_MULT_DOSStub_fdc0 {
  strings:
    $key_fdc0 = { a9 a8 [2] dd b0 [2] 9a b2 [2] dd a3 [2] 93 af [2] 9f a5 [2] 88 ae [2] 93 e0 [2] ae }

  condition:
    any of them
}