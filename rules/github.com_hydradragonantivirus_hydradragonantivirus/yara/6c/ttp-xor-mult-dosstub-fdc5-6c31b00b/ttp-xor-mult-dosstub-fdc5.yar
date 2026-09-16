rule TTP_XOR_MULT_DOSStub_fdc5 {
  strings:
    $key_fdc5 = { a9 ad [2] dd b5 [2] 9a b7 [2] dd a6 [2] 93 aa [2] 9f a0 [2] 88 ab [2] 93 e5 [2] ae }

  condition:
    any of them
}